#include "include/nfcsigner/nfcsigner_plugin.h"

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <winscard.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef HAVE_PODOFO
#include <podofo/podofo.h>
#endif

#define NFCSIGNER_PLUGIN(obj)                                     \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), nfcsigner_plugin_get_type(), \
                              NfcsignerPlugin))

struct _NfcsignerPlugin {
  GObject parent_instance;
};

G_DEFINE_TYPE(NfcsignerPlugin, nfcsigner_plugin, g_object_get_type())

namespace {

using Bytes = std::vector<uint8_t>;

// Chỉ một thao tác thẻ tại một thời điểm: trạng thái PIN đã xác thực trên thẻ
// là chung, hai lệnh xen nhau có thể ký bằng PIN của lệnh kia.
std::atomic<bool> g_busy{false};

// ---------------------------------------------------------------------------
// Lỗi
// ---------------------------------------------------------------------------

struct CardError : std::runtime_error {
  CardError(std::string code, const std::string& message, int sw1 = -1,
            int sw2 = -1)
      : std::runtime_error(message), code(std::move(code)), sw1(sw1), sw2(sw2) {}
  std::string code;
  int sw1;
  int sw2;
};

FlMethodResponse* ErrorResponse(const std::string& code,
                                const std::string& message, int sw1 = -1,
                                int sw2 = -1) {
  g_autoptr(FlValue) details = nullptr;
  if (sw1 >= 0 && sw2 >= 0) {
    details = fl_value_new_map();
    fl_value_set_string_take(details, "sw1", fl_value_new_int(sw1));
    fl_value_set_string_take(details, "sw2", fl_value_new_int(sw2));
  }
  return FL_METHOD_RESPONSE(
      fl_method_error_response_new(code.c_str(), message.c_str(), details));
}

FlMethodResponse* BytesResponse(const Bytes& data) {
  g_autoptr(FlValue) value = fl_value_new_uint8_list(data.data(), data.size());
  return FL_METHOD_RESPONSE(fl_method_success_response_new(value));
}

// ---------------------------------------------------------------------------
// Đọc tham số (trên main thread, trước khi chuyển sang thread nền)
// ---------------------------------------------------------------------------

FlValue* Lookup(FlValue* args, const char* key) {
  if (args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
    return nullptr;
  }
  FlValue* v = fl_value_lookup_string(args, key);
  if (v == nullptr || fl_value_get_type(v) == FL_VALUE_TYPE_NULL) return nullptr;
  return v;
}

std::string RequireString(FlValue* args, const char* key) {
  FlValue* v = Lookup(args, key);
  if (v == nullptr || fl_value_get_type(v) != FL_VALUE_TYPE_STRING) {
    throw CardError("INVALID_PARAMETERS", std::string("Thiếu tham số: ") + key);
  }
  return fl_value_get_string(v);
}

[[maybe_unused]] std::string OptString(FlValue* args, const char* key, const std::string& def) {
  FlValue* v = Lookup(args, key);
  if (v == nullptr || fl_value_get_type(v) != FL_VALUE_TYPE_STRING) return def;
  return fl_value_get_string(v);
}

Bytes OptBytes(FlValue* args, const char* key) {
  FlValue* v = Lookup(args, key);
  if (v == nullptr || fl_value_get_type(v) != FL_VALUE_TYPE_UINT8_LIST) {
    return {};
  }
  const uint8_t* p = fl_value_get_uint8_list(v);
  return Bytes(p, p + fl_value_get_length(v));
}

Bytes RequireBytes(FlValue* args, const char* key) {
  Bytes b = OptBytes(args, key);
  if (b.empty()) {
    throw CardError("INVALID_PARAMETERS", std::string("Thiếu tham số: ") + key);
  }
  return b;
}

int64_t OptInt(FlValue* args, const char* key, int64_t def) {
  FlValue* v = Lookup(args, key);
  if (v == nullptr || fl_value_get_type(v) != FL_VALUE_TYPE_INT) return def;
  return fl_value_get_int(v);
}

[[maybe_unused]] double OptDouble(FlValue* args, const char* key, double def) {
  FlValue* v = Lookup(args, key);
  if (v == nullptr) return def;
  if (fl_value_get_type(v) == FL_VALUE_TYPE_FLOAT) return fl_value_get_float(v);
  if (fl_value_get_type(v) == FL_VALUE_TYPE_INT) return fl_value_get_int(v);
  return def;
}

Bytes HexToBytes(const std::string& hex) {
  if (hex.size() % 2 != 0) {
    throw CardError("INVALID_PARAMETERS", "AID phải có số ký tự hex chẵn.");
  }
  Bytes out;
  for (size_t i = 0; i < hex.size(); i += 2) {
    out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

// ---------------------------------------------------------------------------
// APDU
// ---------------------------------------------------------------------------

Bytes Apdu(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, const Bytes& data,
           bool withLe) {
  if (data.size() > 255) {
    throw CardError("INVALID_PARAMETERS", "Dữ liệu APDU vượt quá 255 byte.");
  }
  Bytes cmd = {cla, ins, p1, p2};
  if (!data.empty()) {
    cmd.push_back(static_cast<uint8_t>(data.size()));
    cmd.insert(cmd.end(), data.begin(), data.end());
  }
  if (withLe) cmd.push_back(0x00);
  return cmd;
}

struct Response {
  Bytes data;
  uint8_t sw1 = 0;
  uint8_t sw2 = 0;
  bool ok() const { return sw1 == 0x90 && sw2 == 0x00; }
};

class Card {
 public:
  Card(SCARDHANDLE handle, DWORD protocol) : handle_(handle), protocol_(protocol) {}

  // Gửi APDU, tự xử lý 61xx (GET RESPONSE) và 6Cxx (gửi lại với Le đúng).
  Response Transmit(Bytes command) {
    Response r = TransmitOnce(command);
    if (r.sw1 == 0x6C) {
      command.back() = r.sw2;
      r = TransmitOnce(command);
    }
    Bytes all = r.data;
    while (r.sw1 == 0x61) {
      r = TransmitOnce({0x00, 0xC0, 0x00, 0x00, r.sw2});
      all.insert(all.end(), r.data.begin(), r.data.end());
    }
    r.data = std::move(all);
    return r;
  }

  void Select(const std::string& aidHex) {
    Response r = Transmit(Apdu(0x00, 0xA4, 0x04, 0x00, HexToBytes(aidHex), true));
    if (!r.ok()) {
      throw CardError("APPLET_NOT_SELECTED", "Không thể chọn Applet.", r.sw1, r.sw2);
    }
  }

  // mode 0x81: ký (PSO:CDS); 0x82: giải mã / INTERNAL AUTHENTICATE.
  void VerifyPin(const std::string& pin, uint8_t mode) {
    Bytes pinBytes(pin.begin(), pin.end());
    Response r = Transmit(Apdu(0x00, 0x20, 0x00, mode, pinBytes, false));
    std::fill(pinBytes.begin(), pinBytes.end(), 0);
    if (r.ok()) return;
    if (r.sw1 == 0x63 && (r.sw2 & 0xF0) == 0xC0) {
      throw CardError("AUTH_ERROR",
                      "Xác thực PIN thất bại. Còn " +
                          std::to_string(r.sw2 & 0x0F) + " lần thử.",
                      r.sw1, r.sw2);
    }
    if (r.sw1 == 0x69 && r.sw2 == 0x83) {
      throw CardError("AUTH_ERROR", "PIN đã bị khóa.", r.sw1, r.sw2);
    }
    throw CardError("AUTH_ERROR", "Xác thực PIN thất bại.", r.sw1, r.sw2);
  }

  Bytes Expect(const Response& r, const std::string& what) {
    if (!r.ok()) {
      throw CardError("COMMUNICATION_ERROR", what + " thất bại.", r.sw1, r.sw2);
    }
    return r.data;
  }

  Bytes ComputeSignature(const Bytes& digestInfo, int keyIndex) {
    uint8_t p2 = keyIndex == 1 ? 0x9B : (keyIndex == 2 ? 0x9C : 0x9A);
    return Expect(Transmit(Apdu(0x00, 0x2A, 0x9E, p2, digestInfo, true)),
                  "Ký số");
  }

  Bytes InternalAuthenticate(const Bytes& digestInfo) {
    return Expect(Transmit(Apdu(0x00, 0x88, 0x00, 0x00, digestInfo, true)),
                  "INTERNAL AUTHENTICATE");
  }

  Bytes PublicKey(const std::string& role) {
    Bytes crt;
    if (role == "sig") crt = {0xB6, 0x00};
    else if (role == "dec") crt = {0xB8, 0x00};
    else if (role == "aut") crt = {0xA4, 0x00};
    else if (role == "sm") crt = {0xA6, 0x00};
    else throw CardError("INVALID_PARAMETERS", "Vai trò khóa không hợp lệ: " + role);
    return Expect(Transmit(Apdu(0x00, 0x47, 0x81, 0x00, crt, true)),
                  "Lấy khóa công khai");
  }

  Bytes Certificate() {
    Expect(Transmit(Apdu(0x00, 0xA5, 0x02, 0x04,
                         {0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21}, true)),
           "Chọn certificate");
    Bytes cert = Expect(Transmit({0x00, 0xCA, 0x7F, 0x21, 0x00}), "Lấy certificate");
    if (cert.empty()) {
      throw CardError("OPERATION_NOT_SUPPORTED", "Certificate trên thẻ rỗng.");
    }
    return cert;
  }

  Bytes Decipher(const Bytes& ciphertext) {
    Bytes full;
    full.reserve(ciphertext.size() + 1);
    full.push_back(0x00);  // padding indicator: PKCS#1 v1.5
    full.insert(full.end(), ciphertext.begin(), ciphertext.end());
    size_t offset = 0;
    while (true) {
      size_t len = std::min<size_t>(255, full.size() - offset);
      bool last = offset + len >= full.size();
      Bytes chunk(full.begin() + offset, full.begin() + offset + len);
      Response r = Transmit(Apdu(last ? 0x00 : 0x10, 0x2A, 0x80, 0x86, chunk, last));
      if (!r.ok()) {
        throw CardError("COMMUNICATION_ERROR", "Giải mã thất bại.", r.sw1, r.sw2);
      }
      if (last) return r.data;
      offset += len;
    }
  }

  int PinRetryCounter() {
    Bytes pw = Expect(Transmit({0x00, 0xCA, 0x00, 0xC4, 0x00}), "Đọc PW status");
    if (pw.size() < 5) {
      throw CardError("COMMUNICATION_ERROR", "PW Status Bytes quá ngắn.");
    }
    return pw[4];
  }

 private:
  Response TransmitOnce(const Bytes& command) {
    const SCARD_IO_REQUEST* pci =
        protocol_ == SCARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1;
    Bytes buffer(65538);
    DWORD len = static_cast<DWORD>(buffer.size());
    LONG rc = SCardTransmit(handle_, pci, command.data(),
                            static_cast<DWORD>(command.size()), nullptr,
                            buffer.data(), &len);
    if (rc != SCARD_S_SUCCESS) {
      throw CardError("COMMUNICATION_ERROR",
                      std::string("SCardTransmit: ") + pcsc_stringify_error(rc));
    }
    if (len < 2) {
      throw CardError("COMMUNICATION_ERROR", "Phản hồi của thẻ quá ngắn.");
    }
    Response r;
    r.sw1 = buffer[len - 2];
    r.sw2 = buffer[len - 1];
    r.data.assign(buffer.begin(), buffer.begin() + (len - 2));
    return r;
  }

  SCARDHANDLE handle_;
  DWORD protocol_;
};

std::vector<std::string> ListReaders(SCARDCONTEXT ctx) {
  DWORD size = 0;
  LONG rc = SCardListReaders(ctx, nullptr, nullptr, &size);
  if (rc != SCARD_S_SUCCESS || size == 0) return {};
  std::vector<char> buf(size);
  rc = SCardListReaders(ctx, nullptr, buf.data(), &size);
  if (rc != SCARD_S_SUCCESS) return {};
  std::vector<std::string> out;
  for (const char* p = buf.data(); *p != '\0'; p += std::strlen(p) + 1) {
    out.emplace_back(p);
  }
  return out;
}

bool IsReaderAttached() {
  SCARDCONTEXT ctx;
  if (SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &ctx) !=
      SCARD_S_SUCCESS) {
    return false;
  }
  bool attached = !ListReaders(ctx).empty();
  SCardReleaseContext(ctx);
  return attached;
}

// Kết nối thẻ và chọn applet. Thử lần lượt từng đầu đọc: máy có thể cắm nhiều
// đầu đọc (ví dụ đầu đọc tích hợp không có thẻ + đầu đọc USB có thẻ BCard).
void WithCard(const std::string& aid, const std::function<void(Card&)>& op) {
  SCARDCONTEXT ctx;
  LONG rc = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &ctx);
  if (rc != SCARD_S_SUCCESS) {
    throw CardError("COMMUNICATION_ERROR",
                    std::string("Không khởi tạo được PC/SC: ") + pcsc_stringify_error(rc));
  }
  struct CtxGuard {
    SCARDCONTEXT c;
    ~CtxGuard() { SCardReleaseContext(c); }
  } ctxGuard{ctx};

  auto readers = ListReaders(ctx);
  if (readers.empty()) {
    throw CardError("COMMUNICATION_ERROR", "Không tìm thấy đầu đọc thẻ.");
  }

  CardError lastError("COMMUNICATION_ERROR", "Không tìm thấy thẻ trong đầu đọc.");
  for (const auto& reader : readers) {
    SCARDHANDLE handle;
    DWORD protocol = 0;
    rc = SCardConnect(ctx, reader.c_str(), SCARD_SHARE_SHARED,
                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &handle, &protocol);
    if (rc != SCARD_S_SUCCESS) continue;
    struct CardGuard {
      SCARDHANDLE h;
      // RESET_CARD: xoá trạng thái PIN đã xác thực khi xong việc.
      ~CardGuard() { SCardDisconnect(h, SCARD_RESET_CARD); }
    } cardGuard{handle};

    Card card(handle, protocol);
    try {
      card.Select(aid);
    } catch (const CardError& e) {
      lastError = e;
      continue;  // thử đầu đọc khác
    }
    op(card);
    return;
  }
  throw lastError;
}

#ifdef HAVE_PODOFO
Bytes SignPdf(Card& card, const Bytes& pdfBytes,
              const std::string& pin, int keyIndex, const std::string& reason,
              const std::string& location, double x, double y, double width,
              double height, int pageNumber, const std::string& signerName,
              const std::string& signDate, const Bytes& imageBytes,
              double imageWidth, double imageHeight) {
  using namespace PoDoFo;
  card.VerifyPin(pin, 0x81);
  Bytes cert = card.Certificate();

  PdfMemDocument document;
  document.LoadFromBuffer(bufferview(reinterpret_cast<const char*>(pdfBytes.data()),
                                     pdfBytes.size()));
  unsigned pageCount = document.GetPages().GetCount();
  unsigned pageIndex = pageNumber > 0 ? static_cast<unsigned>(pageNumber - 1) : 0;
  if (pageIndex >= pageCount) {
    throw CardError("INVALID_PARAMETERS", "Số trang ký vượt quá số trang của PDF.");
  }
  PdfPage& page = document.GetPages().GetPageAt(pageIndex);

  auto& field = page.CreateField<PdfSignature>("BMC-Signature", Rect(x, y, width, height));
  field.SetSignatureReason(PdfString(reason));
  field.SetSignatureLocation(PdfString(location));
  if (!signerName.empty()) field.SetSignerName(PdfString(signerName));
  field.SetSignatureDate(PdfDate::LocalNow());

  auto xobj = document.CreateXObjectForm(Rect(0, 0, width, height));
  {
    PdfPainter painter;
    painter.SetCanvas(*xobj);
    double textX = 4.0;
    if (!imageBytes.empty()) {
      try {
        auto image = document.CreateImage();
        image->LoadFromBuffer(bufferview(
            reinterpret_cast<const char*>(imageBytes.data()), imageBytes.size()));
        if (image->GetWidth() > 0 && image->GetHeight() > 0) {
          double w = std::min(imageWidth, width / 2.0);
          double h = std::min(imageHeight, height - 4.0);
          painter.DrawImage(*image, 2.0, (height - h) / 2.0,
                            w / image->GetWidth(), h / image->GetHeight());
          textX = w + 6.0;
        }
      } catch (const PdfError& e) {
        std::cerr << "nfcsigner: bỏ qua ảnh chữ ký: " << e.what() << std::endl;
      }
    }

    std::vector<std::string> lines;
    if (!signerName.empty()) lines.push_back("Người ký: " + signerName);
    if (!signDate.empty()) lines.push_back("Ngày ký: " + signDate);
    if (!reason.empty()) lines.push_back("Lý do: " + reason);
    if (!location.empty()) lines.push_back("Địa điểm: " + location);

    if (!lines.empty()) {
      PdfFont* font = document.GetFonts().SearchFont("DejaVu Sans");
      if (font == nullptr) {
        font = &document.GetFonts().GetStandard14Font(PdfStandard14FontType::Helvetica);
      }
      double size = height < 45.0 ? 6.5 : 8.0;
      painter.TextState.SetFont(*font, size);
      double lineY = height - size - 3.0;
      for (const auto& line : lines) {
        if (lineY < 1.0) break;
        painter.DrawText(line, textX, lineY);
        lineY -= size * 1.3;
      }
    }
    painter.FinishDrawing();
  }
  field.MustGetWidget().SetAppearanceStream(*xobj);

  PdfSignerCmsParams params;
  params.Hashing = PdfHashingAlgorithm::SHA256;
  // ServiceDoWrapDigest: PoDoFo đưa vào DigestInfo(SHA-256(signed attributes))
  // — đúng thứ PSO:CDS cần ký.
  params.Flags = static_cast<PdfSignerCmsFlags>(
      static_cast<int>(PdfSignerCmsFlags::ServiceDoDryRun) |
      static_cast<int>(PdfSignerCmsFlags::ServiceDoWrapDigest));
  params.SigningService = [&](bufferview hashToSign, bool dryrun, charbuff& signedHash) {
    if (dryrun) {
      signedHash.resize(512);  // đủ cho RSA-4096
      return;
    }
    Bytes digestInfo(hashToSign.begin(), hashToSign.end());
    Bytes sig = card.ComputeSignature(digestInfo, keyIndex);
    signedHash.assign(reinterpret_cast<const char*>(sig.data()), sig.size());
  };

  PdfSignerCms signer(bufferview(reinterpret_cast<const char*>(cert.data()), cert.size()),
                      params);
  std::vector<char> buffer;
  {
    VectorStreamDevice device(buffer);
    device.Write(reinterpret_cast<const char*>(pdfBytes.data()), pdfBytes.size());
    SignDocument(document, device, signer, field);
  }
  return Bytes(buffer.begin(), buffer.end());
}
#endif

// ---------------------------------------------------------------------------
// Chạy thao tác thẻ trên thread nền, trả kết quả trên main thread
// ---------------------------------------------------------------------------

struct PendingResponse {
  FlMethodCall* call;
  FlMethodResponse* response;
};

gboolean RespondOnMain(gpointer data) {
  auto* p = static_cast<PendingResponse*>(data);
  g_autoptr(GError) error = nullptr;
  if (!fl_method_call_respond(p->call, p->response, &error)) {
    g_warning("nfcsigner: không gửi được phản hồi: %s", error->message);
  }
  g_object_unref(p->response);
  g_object_unref(p->call);
  delete p;
  return G_SOURCE_REMOVE;
}

void RunCardOperation(FlMethodCall* call, std::function<FlMethodResponse*()> work) {
  bool expected = false;
  if (!g_busy.compare_exchange_strong(expected, true)) {
    g_autoptr(FlMethodResponse) r =
        ErrorResponse("BUSY", "Đang có một thao tác thẻ khác chưa hoàn tất.");
    fl_method_call_respond(call, r, nullptr);
    return;
  }
  g_object_ref(call);
  std::thread([call, work = std::move(work)]() {
    FlMethodResponse* response = nullptr;
    try {
      response = work();
    } catch (const CardError& e) {
      response = ErrorResponse(e.code, e.what(), e.sw1, e.sw2);
#ifdef HAVE_PODOFO
    } catch (const PoDoFo::PdfError& e) {
      response = ErrorResponse("PDF_SIGN_ERROR", std::string("Lỗi PDF: ") + e.what());
#endif
    } catch (const std::exception& e) {
      response = ErrorResponse("COMMUNICATION_ERROR", e.what());
    }
    g_busy = false;
    g_idle_add(RespondOnMain, new PendingResponse{call, response});
  }).detach();
}

void HandleMethodCall(FlMethodCall* call) {
  const gchar* method = fl_method_call_get_name(call);
  FlValue* args = fl_method_call_get_args(call);

  try {
    if (strcmp(method, "getPlatformVersion") == 0) {
      g_autofree gchar* version = g_strdup_printf("Linux");
      g_autoptr(FlValue) v = fl_value_new_string(version);
      g_autoptr(FlMethodResponse) r = FL_METHOD_RESPONSE(fl_method_success_response_new(v));
      fl_method_call_respond(call, r, nullptr);
      return;
    }
    if (strcmp(method, "isCardReaderAttached") == 0) {
      g_autoptr(FlValue) v = fl_value_new_bool(IsReaderAttached());
      g_autoptr(FlMethodResponse) r = FL_METHOD_RESPONSE(fl_method_success_response_new(v));
      fl_method_call_respond(call, r, nullptr);
      return;
    }
    if (strcmp(method, "cancelNfc") == 0 || strcmp(method, "cancelNfcWait") == 0) {
      // Đầu đọc cắm cố định: không có gì đang chờ để huỷ.
      g_autoptr(FlValue) v = fl_value_new_bool(TRUE);
      g_autoptr(FlMethodResponse) r = FL_METHOD_RESPONSE(fl_method_success_response_new(v));
      fl_method_call_respond(call, r, nullptr);
      return;
    }

    // Đọc tham số trên main thread; thread nền chỉ dùng bản sao C++.
    if (strcmp(method, "generateSignature") == 0) {
      auto aid = RequireString(args, "appletID");
      auto pin = RequireString(args, "pin");
      auto data = RequireBytes(args, "dataToSign");
      int keyIndex = static_cast<int>(OptInt(args, "keyIndex", 0));
      RunCardOperation(call, [=]() {
        Bytes sig;
        WithCard(aid, [&](Card& card) {
          card.VerifyPin(pin, 0x81);
          sig = card.ComputeSignature(data, keyIndex);
        });
        return BytesResponse(sig);
      });
    } else if (strcmp(method, "internalAuthenticate") == 0) {
      auto aid = RequireString(args, "appletID");
      auto pin = RequireString(args, "pin");
      auto data = RequireBytes(args, "dataToSign");
      RunCardOperation(call, [=]() {
        Bytes sig;
        WithCard(aid, [&](Card& card) {
          card.VerifyPin(pin, 0x82);
          sig = card.InternalAuthenticate(data);
        });
        return BytesResponse(sig);
      });
    } else if (strcmp(method, "getRsaPublicKey") == 0) {
      auto aid = RequireString(args, "appletID");
      auto role = RequireString(args, "keyRole");
      RunCardOperation(call, [=]() {
        Bytes key;
        WithCard(aid, [&](Card& card) { key = card.PublicKey(role); });
        return BytesResponse(key);
      });
    } else if (strcmp(method, "getCertificate") == 0) {
      auto aid = RequireString(args, "appletID");
      RunCardOperation(call, [=]() {
        Bytes cert;
        WithCard(aid, [&](Card& card) { cert = card.Certificate(); });
        return BytesResponse(cert);
      });
    } else if (strcmp(method, "decryptData") == 0) {
      auto aid = RequireString(args, "appletID");
      auto pin = RequireString(args, "pin");
      auto data = RequireBytes(args, "encryptedData");
      RunCardOperation(call, [=]() {
        Bytes plain;
        WithCard(aid, [&](Card& card) {
          card.VerifyPin(pin, 0x82);
          plain = card.Decipher(data);
        });
        return BytesResponse(plain);
      });
    } else if (strcmp(method, "getPinRetryCounter") == 0) {
      auto aid = RequireString(args, "appletID");
      RunCardOperation(call, [=]() {
        int counter = 0;
        WithCard(aid, [&](Card& card) { counter = card.PinRetryCounter(); });
        g_autoptr(FlValue) v = fl_value_new_int(counter);
        return FL_METHOD_RESPONSE(fl_method_success_response_new(v));
      });
    } else if (strcmp(method, "signPdf") == 0) {
#ifdef HAVE_PODOFO
      auto aid = RequireString(args, "appletID");
      auto pin = RequireString(args, "pin");
      auto pdf = RequireBytes(args, "pdfBytes");
      int keyIndex = static_cast<int>(OptInt(args, "keyIndex", 0));
      auto reason = OptString(args, "reason", "");
      auto location = OptString(args, "location", "");
      FlValue* cfg = Lookup(args, "signatureConfig");
      double x = OptDouble(cfg, "x", 36.0), y = OptDouble(cfg, "y", 700.0);
      double w = OptDouble(cfg, "width", 200.0), h = OptDouble(cfg, "height", 50.0);
      int page = static_cast<int>(OptInt(cfg, "pageNumber", 1));
      auto signer = OptString(cfg, "signerName", "");
      auto date = OptString(cfg, "signDate", "");
      auto image = OptBytes(cfg, "signatureImage");
      double iw = OptDouble(cfg, "signatureImageWidth", 50.0);
      double ih = OptDouble(cfg, "signatureImageHeight", 50.0);
      RunCardOperation(call, [=]() {
        Bytes out;
        WithCard(aid, [&](Card& card) {
          out = SignPdf(card, pdf, pin, keyIndex, reason, location, x, y,
                        w, h, page, signer, date, image, iw, ih);
        });
        return BytesResponse(out);
      });
#else
      g_autoptr(FlMethodResponse) r = ErrorResponse(
          "OPERATION_NOT_SUPPORTED",
          "Plugin được build không kèm PoDoFo nên không ký được PDF.");
      fl_method_call_respond(call, r, nullptr);
#endif
    } else {
      g_autoptr(FlMethodResponse) r =
          FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
      fl_method_call_respond(call, r, nullptr);
    }
  } catch (const CardError& e) {
    g_autoptr(FlMethodResponse) r = ErrorResponse(e.code, e.what());
    fl_method_call_respond(call, r, nullptr);
  }
}

}  // namespace

static void nfcsigner_plugin_dispose(GObject* object) {
  G_OBJECT_CLASS(nfcsigner_plugin_parent_class)->dispose(object);
}

static void nfcsigner_plugin_class_init(NfcsignerPluginClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = nfcsigner_plugin_dispose;
}

static void nfcsigner_plugin_init(NfcsignerPlugin* self) {}

static void method_call_cb(FlMethodChannel* channel, FlMethodCall* method_call,
                           gpointer user_data) {
  HandleMethodCall(method_call);
}

void nfcsigner_plugin_register_with_registrar(FlPluginRegistrar* registrar) {
  NfcsignerPlugin* plugin =
      NFCSIGNER_PLUGIN(g_object_new(nfcsigner_plugin_get_type(), nullptr));

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) channel =
      fl_method_channel_new(fl_plugin_registrar_get_messenger(registrar),
                            "nfcsigner", FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(channel, method_call_cb,
                                            g_object_ref(plugin), g_object_unref);

  g_object_unref(plugin);
}

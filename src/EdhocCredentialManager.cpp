#include <exception>
#include <future>
#include <iostream>
#include <stdexcept>

#include "EdhocCredentialManager.h"
#include "UserContext.h"
#include "Utils.h"

static constexpr const char* kFormat = "format";
static constexpr const char* kPrivateKeyId = "privateKeyID";
static constexpr const char* kPublicKey = "publicKey";
static constexpr const char* kKid = "kid";
static constexpr const char* kIsCBOR = "isCBOR";
static constexpr const char* kCredentials = "credentials";
static constexpr const char* kX5chain = "x5chain";
static constexpr const char* kCertificate = "certificate";
static constexpr const char* kCertificates = "certificates";
static constexpr const char* kX5t = "x5t";
static constexpr const char* kHash = "hash";
static constexpr const char* kHashAlgorithm = "hashAlgorithm";

static constexpr const char* kUnsupportedCredentialTypeError =
    "Unsupported credential type specified";
static constexpr const char* kInvalidInputCredentialTypeError =
    "Invalid credentials object specified";
static constexpr const char* kInvalidInputDataErrorKid =
    "Invalid input data for Key ID";
static constexpr const char* kInvalidInputDataErrorX509Chain =
    "Invalid input data for X.509 chain";
static constexpr const char* kInvalidInputDataErrorX509Hash =
    "Invalid input data for X.509 hash";
static constexpr const char* kErrorObjectExpected = "Object expected";
static constexpr const char* kErrorFunctionExpected = "Function expected";
static constexpr const char* kFetch = "fetch";
static constexpr const char* kVerify = "verify";

void convert_js_to_edhoc_kid(const Napi::Object& jsObject,
                             struct edhoc_auth_creds* credentials) {
  Napi::Object kidObj = jsObject.Get(kKid).As<Napi::Object>();
  if (!kidObj.Has(kIsCBOR) || !kidObj.Has(kKid) || !kidObj.Has(kCredentials)) {
    throw Napi::Error::New(jsObject.Env(), kInvalidInputDataErrorKid);
  }

  credentials->label = EDHOC_COSE_HEADER_KID;

  if (kidObj.Get(kKid).IsNumber()) {
    int64_t numeric = kidObj.Get(kKid).As<Napi::Number>().Int64Value();
    if (numeric >= ONE_BYTE_CBOR_INT_MIN_VALUE &&
        numeric <= ONE_BYTE_CBOR_INT_MAX_VALUE) {
      credentials->key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
      credentials->key_id.key_id_int = (int32_t)numeric;
    } else {
      size_t length = 0;
      Utils::EncodeInt64ToBuffer(
          numeric, credentials->key_id.key_id_bstr, &length);
      credentials->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
      credentials->key_id.key_id_bstr_length = length;
    }
  } else if (kidObj.Get(kKid).IsBuffer()) {
    Napi::Buffer<uint8_t> buffer = kidObj.Get(kKid).As<Napi::Buffer<uint8_t>>();
    credentials->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
    credentials->key_id.key_id_bstr_length = buffer.Length();
    memcpy(credentials->key_id.key_id_bstr, buffer.Data(), buffer.Length());
  } else {
    throw Napi::Error::New(jsObject.Env(), kInvalidInputDataErrorKid);
  }

  Napi::Buffer<uint8_t> credBuffer =
      kidObj.Get(kCredentials).As<Napi::Buffer<uint8_t>>();
  credentials->key_id.cred = credBuffer.Data();
  credentials->key_id.cred_len = credBuffer.Length();
  credentials->key_id.cred_is_cbor =
      kidObj.Get(kIsCBOR).As<Napi::Boolean>().Value();
}

void convert_js_to_edhoc_x5chain(const Napi::Object& jsObject,
                                 struct edhoc_auth_creds* credentials) {
  Napi::Object x5chainObj = jsObject.Get(kX5chain).As<Napi::Object>();
  if (!x5chainObj.Has(kCertificates)) {
    throw Napi::Error::New(jsObject.Env(), kInvalidInputDataErrorX509Chain);
  }

  credentials->label = EDHOC_COSE_HEADER_X509_CHAIN;

  Napi::Array certArray = x5chainObj.Get(kCertificates).As<Napi::Array>();
  size_t nr_of_certs = certArray.Length();
  credentials->x509_chain.nr_of_certs = nr_of_certs;

  for (size_t i = 0; i < nr_of_certs; ++i) {
    Napi::Buffer<uint8_t> certBuffer = certArray.Get(i).As<Napi::Buffer<uint8_t>>();
    credentials->x509_chain.cert[i] = certBuffer.Data();
    credentials->x509_chain.cert_len[i] = certBuffer.Length();
  }
}

void convert_js_to_edhoc_x5t(const Napi::Object& jsObject,
                             struct edhoc_auth_creds* credentials) {
  Napi::Object x5tObj = jsObject.Get(kX5t).As<Napi::Object>();
  if (!x5tObj.Has(kCertificate) || !x5tObj.Has(kHash) ||
      !x5tObj.Has(kHashAlgorithm)) {
    throw Napi::Error::New(jsObject.Env(), kInvalidInputDataErrorX509Hash);
  }

  credentials->label = EDHOC_COSE_HEADER_X509_HASH;

  Napi::Buffer<uint8_t> certBuffer =
      x5tObj.Get(kCertificate).As<Napi::Buffer<uint8_t>>();
  credentials->x509_hash.cert = certBuffer.Data();
  credentials->x509_hash.cert_len = certBuffer.Length();

  Napi::Buffer<uint8_t> hashBuffer =
      x5tObj.Get(kHash).As<Napi::Buffer<uint8_t>>();
  credentials->x509_hash.cert_fp = hashBuffer.Data();
  credentials->x509_hash.cert_fp_len = hashBuffer.Length();

  credentials->x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
  credentials->x509_hash.alg_int =
      x5tObj.Get(kHashAlgorithm).As<Napi::Number>().Int32Value();
}

Napi::Object convert_edhoc_kid_to_js(const Napi::Env& env,
                                     const struct edhoc_auth_cred_key_id& kid) {
  Napi::Object obj = Napi::Object::New(env);
  obj.Set(kIsCBOR, Napi::Boolean::New(env, kid.cred_is_cbor));

  if (kid.encode_type == EDHOC_ENCODE_TYPE_INTEGER) {
    obj.Set(kKid, Napi::Number::New(env, kid.key_id_int));
  } else {
    obj.Set(kKid,
            Napi::Buffer<uint8_t>::Copy(
                env, kid.key_id_bstr, kid.key_id_bstr_length));
  }

  obj.Set(kCredentials,
          Napi::Buffer<uint8_t>::Copy(env, kid.cred, kid.cred_len));
  return obj;
}

Napi::Object convert_edhoc_x5chain_to_js(
    const Napi::Env& env, const struct edhoc_auth_cred_x509_chain& x509_chain) {
  Napi::Object obj = Napi::Object::New(env);
  Napi::Array certArray = Napi::Array::New(env, x509_chain.nr_of_certs);

  for (size_t i = 0; i < x509_chain.nr_of_certs; ++i) {
    certArray.Set(i, Napi::Buffer<uint8_t>::Copy(env, x509_chain.cert[i], x509_chain.cert_len[i]));
  }

  obj.Set(kCertificates, certArray);
  return obj;
}

Napi::Object convert_edhoc_x5t_to_js(
    const Napi::Env& env, const struct edhoc_auth_cred_x509_hash& x509_hash) {
  Napi::Object obj = Napi::Object::New(env);
  obj.Set(kCertificate,
          Napi::Buffer<uint8_t>::Copy(env, x509_hash.cert, x509_hash.cert_len));
  obj.Set(kHash,
          Napi::Buffer<uint8_t>::Copy(
              env, x509_hash.cert_fp, x509_hash.cert_fp_len));
  obj.Set(kHashAlgorithm, Napi::Number::New(env, x509_hash.alg_int));
  return obj;
}

EdhocCredentialManager::EdhocCredentialManager(
    Napi::Object& jsCredentialManager) {
  if (!jsCredentialManager.IsObject()) {
    Napi::Error::New(jsCredentialManager.Env(), kErrorObjectExpected)
        .ThrowAsJavaScriptException();
  }
  credentialManagerRef = Napi::Persistent(jsCredentialManager);
  SetFunction(kFetch, fetchTsfn);
  SetFunction(kVerify, verifyTsfn);

  credentials.fetch = FetchCredentials;
  credentials.verify = VerifyCredentials;
}

EdhocCredentialManager::~EdhocCredentialManager() {
  credentialManagerRef.Reset();
  fetchTsfn.Release();
  verifyTsfn.Release();
  for (auto& ref : credentialReferences) {
    ref.Reset();
  }
  credentialReferences.clear();
}

void EdhocCredentialManager::SetFunction(const char* name,
                                         Napi::ThreadSafeFunction& tsfn) {
  Napi::Env env = credentialManagerRef.Env();
  Napi::HandleScope scope(env);
  Napi::Function jsFunction =
      credentialManagerRef.Value().Get(name).As<Napi::Function>();
  if (!jsFunction.IsFunction()) {
    Napi::Error::New(env, kErrorFunctionExpected).ThrowAsJavaScriptException();
  }
  tsfn = Napi::ThreadSafeFunction::New(env, jsFunction, name, 0, 1);
}

int EdhocCredentialManager::FetchCredentials(
    void* user_context, struct edhoc_auth_creds* credentials) {
  UserContext* context = static_cast<UserContext*>(user_context);
  EdhocCredentialManager* manager = context->GetCredentialManager();
  return manager->callFetchCredentials(context, credentials);
}

int EdhocCredentialManager::VerifyCredentials(
    void* user_context,
    struct edhoc_auth_creds* credentials,
    const uint8_t** public_key_reference,
    size_t* public_key_length) {
  UserContext* context = static_cast<UserContext*>(user_context);
  EdhocCredentialManager* manager = context->GetCredentialManager();
  return manager->callVerifyCredentials(
      context, credentials, public_key_reference, public_key_length);
}

int EdhocCredentialManager::callFetchCredentials(
    const void* user_context, struct edhoc_auth_creds* credentials) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  fetchTsfn.BlockingCall([this, &user_context, &promise, &credentials](
                             Napi::Env env, Napi::Function jsCallback) {
    Napi::HandleScope scope(env);
    std::vector<napi_value> arguments = {
        static_cast<const UserContext*>(user_context)->parent.Value()};
    Utils::InvokeJSFunctionWithPromiseHandling(
        env,
        credentialManagerRef.Value(),
        jsCallback,
        arguments,
        [this, &promise, &credentials](Napi::Env env, Napi::Value result) {
          Napi::HandleScope scope(env);
          auto credsObj = result.As<Napi::Object>();
          credentialReferences.push_back(Napi::Persistent(credsObj));

          if (credsObj.IsObject() == false || credsObj.Has(kFormat) == false) {
            promise.set_value(EDHOC_ERROR_CREDENTIALS_FAILURE);
            throw Napi::Error::New(env, kInvalidInputCredentialTypeError);
          }
          int label = credsObj.Get(kFormat).As<Napi::Number>().Int32Value();

          switch (label) {
            case EDHOC_COSE_HEADER_KID:
              convert_js_to_edhoc_kid(credsObj, credentials);
              break;
            case EDHOC_COSE_HEADER_X509_CHAIN:
              convert_js_to_edhoc_x5chain(credsObj, credentials);
              break;
            case EDHOC_COSE_HEADER_X509_HASH:
              convert_js_to_edhoc_x5t(credsObj, credentials);
              break;
            default:
              throw Napi::Error::New(env, kUnsupportedCredentialTypeError);
          }
          
          if (credsObj.Has(kPrivateKeyId) &&
              !credsObj.Get(kPrivateKeyId).IsNull()) {
            Napi::Buffer<uint8_t> privKeyIdBuffer =
                credsObj.Get(kPrivateKeyId).As<Napi::Buffer<uint8_t>>();
            memcpy(credentials->priv_key_id,
                   privKeyIdBuffer.Data(),
                   privKeyIdBuffer.Length());
          }

          promise.set_value(EDHOC_SUCCESS);
        });
  });

  future.wait();
  return future.get();
}

int EdhocCredentialManager::callVerifyCredentials(
    const void* user_context,
    struct edhoc_auth_creds* credentials,
    const uint8_t** public_key_reference,
    size_t* public_key_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  verifyTsfn.BlockingCall([this,
                           &user_context,
                           &promise,
                           &credentials,
                           &public_key_reference,
                           &public_key_length](Napi::Env env,
                                               Napi::Function jsCallback) {
    Napi::HandleScope scope(env);
    Napi::Object resultObject = Napi::Object::New(env);
    resultObject.Set(kFormat, Napi::Number::New(env, credentials->label));

    switch (credentials->label) {
      case EDHOC_COSE_HEADER_KID:
        resultObject.Set(kKid,
                         convert_edhoc_kid_to_js(env, credentials->key_id));
        break;
      case EDHOC_COSE_HEADER_X509_CHAIN:
        resultObject.Set(
            kX5chain,
            convert_edhoc_x5chain_to_js(env, credentials->x509_chain));
        break;
      case EDHOC_COSE_HEADER_X509_HASH:
        resultObject.Set(kX5t,
                         convert_edhoc_x5t_to_js(env, credentials->x509_hash));
        break;
      default:
        throw Napi::Error::New(env, kUnsupportedCredentialTypeError);
    }

    std::vector<napi_value> arguments = {
        static_cast<const UserContext*>(user_context)->parent.Value(),
        resultObject};

    Utils::InvokeJSFunctionWithPromiseHandling(
        env,
        credentialManagerRef.Value(),
        jsCallback,
        arguments,
        [this, &promise, &credentials, &public_key_reference, &public_key_length](
            Napi::Env env, Napi::Value result) {
          Napi::HandleScope scope(env);
          Napi::Object credsObj = result.As<Napi::Object>();
          credentialReferences.push_back(Napi::Persistent(credsObj));
          if (credsObj.IsObject() == false) {
            promise.set_value(EDHOC_ERROR_CREDENTIALS_FAILURE);
            throw Napi::Error::New(env, kInvalidInputCredentialTypeError);
          }

          int label = credsObj.Get(kFormat).As<Napi::Number>().Int32Value();
          switch (label) {
            case EDHOC_COSE_HEADER_KID:
              convert_js_to_edhoc_kid(credsObj, credentials);
              break;
            case EDHOC_COSE_HEADER_X509_CHAIN:
              convert_js_to_edhoc_x5chain(credsObj, credentials);
              break;
            case EDHOC_COSE_HEADER_X509_HASH:
              convert_js_to_edhoc_x5t(credsObj, credentials);
              break;
            default:
              throw Napi::Error::New(env, kUnsupportedCredentialTypeError);
          }

          if (credsObj.Has(kPublicKey) && !credsObj.Get(kPublicKey).IsNull()) {
            Napi::Buffer<uint8_t> publicKeyBuffer =
                credsObj.Get(kPublicKey).As<Napi::Buffer<uint8_t>>();
            *public_key_reference = publicKeyBuffer.Data();
            *public_key_length = publicKeyBuffer.Length();
          }

          promise.set_value(EDHOC_SUCCESS);
        });
  });

  future.wait();
  return future.get();
}

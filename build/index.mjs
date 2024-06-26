var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __decorateClass = (decorators, target, key, kind) => {
  var result = kind > 1 ? void 0 : kind ? __getOwnPropDesc(target, key) : target;
  for (var i = decorators.length - 1, decorator; i >= 0; i--)
    if (decorator = decorators[i])
      result = (kind ? decorator(target, key, result) : decorator(result)) || result;
  if (kind && result)
    __defProp(target, key, result);
  return result;
};
var __decorateParam = (index, decorator) => (target, key) => decorator(target, key, index);

// src/module.ts
import { Module } from "@nestjs/common";

// src/service.ts
import { Injectable, Inject } from "@nestjs/common";
import fetch, { Headers } from "node-fetch";
import * as crypto from "crypto";

// src/error.ts
var PARAM_ERROR = class extends Error {
  constructor(message = "\u8BF7\u6839\u636E\u9519\u8BEF\u63D0\u793A\u6B63\u786E\u4F20\u5165\u53C2\u6570") {
    super(`\u53C2\u6570\u9519\u8BEF\uFF08${message}\uFF09`);
    this.name = "PARAM_ERROR";
  }
};
var INVALID_REQUEST = class extends Error {
  constructor(message = "\u8BF7\u53C2\u9605 \u63A5\u53E3\u89C4\u5219\uFF1Ahttps://pay.weixin.qq.com/docs/merchant/development/interface-rules/basic-rules.html") {
    super(`HTTP \u8BF7\u6C42\u4E0D\u7B26\u5408\u5FAE\u4FE1\u652F\u4ED8 APIv3 \u63A5\u53E3\u89C4\u5219\uFF08${message}\uFF09`);
    this.name = "INVALID_REQUEST";
  }
};
var SIGN_ERROR = class extends Error {
  constructor(message = "\u8BF7\u53C2\u9605 \u7B7E\u540D\u5E38\u89C1\u95EE\u9898\uFF1Ahttps://pay.weixin.qq.com/docs/merchant/development/interface-rules/signature-faqs.html") {
    super(`\u9A8C\u8BC1\u4E0D\u901A\u8FC7\uFF08${message}\uFF09`);
    this.name = "SIGN_ERROR";
  }
};
var APPID_MCHID_NOT_MATCH = class extends Error {
  constructor(message = "\u8BF7\u786E\u8BA4AppID\u548Cmch_id\u662F\u5426\u5339\u914D") {
    super(`appid\u548Cmchid\u4E0D\u5339\u914D\uFF08${message}\uFF09`);
    this.name = "APPID_MCHID_NOT_MATCH";
  }
};
var MCH_NOT_EXISTS = class extends Error {
  constructor(message = "\u8BF7\u786E\u8BA4\u5546\u6237\u53F7\u662F\u5426\u6B63\u786E") {
    super(`\u5546\u6237\u4E0D\u5B58\u5728\uFF08${message}\uFF09`);
    this.name = "MCH_NOT_EXISTS";
  }
};
var ORDER_CLOSED = class extends Error {
  constructor(message = "\u5F53\u524D\u8BA2\u5355\u5DF2\u5173\u95ED\uFF0C\u8BF7\u91CD\u65B0\u4E0B\u5355") {
    super(`\u8BA2\u5355\u5DF2\u5173\u95ED\uFF08${message}\uFF09`);
    this.name = "ORDER_CLOSED";
  }
};
var ACCOUNT_ERROR = class extends Error {
  constructor(message = "\u7528\u6237\u8D26\u53F7\u5F02\u5E38\uFF0C\u65E0\u9700\u66F4\u591A\u64CD\u4F5C") {
    super(`\u8D26\u53F7\u5F02\u5E38\uFF08${message}\uFF09`);
    this.name = "ACCOUNT_ERROR";
  }
};
var NO_AUTH = class extends Error {
  constructor(message = "\u5546\u6237\u524D\u5F80\u7533\u8BF7\u6B64\u63A5\u53E3\u76F8\u5173\u6743\u9650") {
    super(`\u5546\u6237\u65E0\u6743\u9650\uFF08${message}\uFF09`);
    this.name = "NO_AUTH";
  }
};
var NOT_ENOUGH = class extends Error {
  constructor(message = "\u7528\u6237\u8D26\u53F7\u4F59\u989D\u4E0D\u8DB3\uFF0C\u8BF7\u7528\u6237\u5145\u503C\u6216\u66F4\u6362\u652F\u4ED8\u5361\u540E\u518D\u652F\u4ED8") {
    super(`\u4F59\u989D\u4E0D\u8DB3\uFF08${message}\uFF09`);
    this.name = "NOT_ENOUGH";
  }
};
var OUT_TRADE_NO_USED = class extends Error {
  constructor(message = "\u8BF7\u6838\u5B9E\u5546\u6237\u8BA2\u5355\u53F7\u662F\u5426\u91CD\u590D\u63D0\u4EA4") {
    super(`\u5546\u6237\u8BA2\u5355\u53F7\u91CD\u590D\uFF08${message}\uFF09`);
    this.name = "OUT_TRADE_NO_USED";
  }
};
var RULE_LIMIT = class extends Error {
  constructor(message = "\u56E0\u4E1A\u52A1\u89C4\u5219\u9650\u5236\u8BF7\u6C42\u9891\u7387\uFF0C\u8BF7\u67E5\u770B\u63A5\u53E3\u8FD4\u56DE\u7684\u8BE6\u7EC6\u4FE1\u606F") {
    super(`\u4E1A\u52A1\u89C4\u5219\u9650\u5236\uFF08${message}\uFF09`);
    this.name = "ORDER_CLOSED";
  }
};
var TRADE_ERROR = class extends Error {
  constructor(message = "\u56E0\u4E1A\u52A1\u539F\u56E0\u4EA4\u6613\u5931\u8D25\uFF0C\u8BF7\u67E5\u770B\u63A5\u53E3\u8FD4\u56DE\u7684\u8BE6\u7EC6\u4FE1\u606F") {
    super(`\u4EA4\u6613\u9519\u8BEF\uFF08${message}\uFF09`);
    this.name = "TRADE_ERROR";
  }
};
var ORDER_NOT_EXIST = class extends Error {
  constructor(message = "\u8BF7\u68C0\u67E5\u8BA2\u5355\u662F\u5426\u53D1\u8D77\u8FC7\u4EA4\u6613") {
    super(`\u8BA2\u5355\u4E0D\u5B58\u5728\uFF08${message}\uFF09`);
    this.name = "ORDER_NOT_EXIST";
  }
};
var FREQUENCY_LIMITED = class extends Error {
  constructor(message = "\u8BF7\u964D\u4F4E\u8BF7\u6C42\u63A5\u53E3\u9891\u7387") {
    super(`\u9891\u7387\u9650\u5236\uFF08${message}\uFF09`);
    this.name = "FREQUENCY_LIMITED";
  }
};
var BANK_ERROR = class extends Error {
  constructor(message = "\u94F6\u884C\u7CFB\u7EDF\u5F02\u5E38\uFF0C\u8BF7\u7528\u76F8\u540C\u53C2\u6570\u91CD\u65B0\u8C03\u7528") {
    super(`\u94F6\u884C\u7CFB\u7EDF\u5F02\u5E38\uFF08${message}\uFF09`);
    this.name = "TRADE_NOT_EXIST";
  }
};
var INVALID_TRANSACTIONID = class extends Error {
  constructor(message = "\u8BF7\u68C0\u67E5\u5FAE\u4FE1\u652F\u4ED8\u8BA2\u5355\u53F7\u662F\u5426\u6B63\u786E") {
    super(`\u8BA2\u5355\u53F7\u975E\u6CD5\uFF08${message}\uFF09`);
    this.name = "INVALID_TRANSACTIONID";
  }
};
var OPENID_MISMATCH = class extends Error {
  constructor(message = "\u8BF7\u786E\u8BA4OpenID\u548CAppID\u662F\u5426\u5339\u914D") {
    super(`OpenID\u548CAppID\u4E0D\u5339\u914D\uFF08${message}\uFF09`);
    this.name = "OPENID_MISMATCH";
  }
};
var SYSTEM_ERROR = class extends Error {
  constructor(message = "\u7CFB\u7EDF\u5F02\u5E38\uFF0C\u8BF7\u7528\u76F8\u540C\u53C2\u6570\u91CD\u65B0\u8C03\u7528") {
    super(`\u7CFB\u7EDF\u9519\u8BEF\uFF08${message}\uFF09`);
    this.name = "SYSTEM_ERROR";
  }
};

// src/types.ts
var AllowMethod = /* @__PURE__ */ ((AllowMethod2) => {
  AllowMethod2["GET"] = "GET";
  AllowMethod2["POST"] = "POST";
  AllowMethod2["PUT"] = "PUT";
  AllowMethod2["DELETE"] = "DELETE";
  AllowMethod2["PATCH"] = "PATCH";
  return AllowMethod2;
})(AllowMethod || {});
var BaseService = class {
};

// src/service.ts
var WechatService = class extends BaseService {
  constructor(options) {
    super();
    this.URL = "";
    this.TIMESTAMP = 0;
    this.NONCE_STR = "";
    this.METHOD = "GET" /* GET */;
    this.SCHEMA = "WECHATPAY2-SHA256-RSA2048";
    this.PRIMARY_DOMAIN = "https://api.mch.weixin.qq.com";
    this.certificates = [];
    this.options = options;
    this.init("GET" /* GET */, "");
    this.getCertificates().then((certificates) => {
      this.certificates = certificates;
    });
  }
  /**
   * 初始化 请求方法、请求地址、时间戳和随机字符串
   */
  async init(method, url) {
    this.METHOD = method;
    this.URL = url;
    this.TIMESTAMP = this.getTimestamp();
    this.NONCE_STR = this.generateNonceStr();
  }
  /**
   * 生成32位随机字符串，包含数字、大写字母
   */
  generateNonceStr() {
    return crypto.randomBytes(32).toString("hex").substring(0, 32).toUpperCase();
  }
  /**
   * 格林威治时间1970年01月01日00时00分00秒(北京时间1970年01月01日08时00分00秒)起至现在的总秒数
   */
  getTimestamp() {
    return Math.floor((/* @__PURE__ */ new Date()).getTime() / 1e3);
  }
  /**
   * 获取签名值
   */
  getSignature(requetBody = "") {
    const data = `${this.METHOD}
${this.URL}
${this.TIMESTAMP}
${this.NONCE_STR}
${requetBody}
`;
    const signature = crypto.createSign("RSA-SHA256").update(data).sign(this.options.privateKey, "base64");
    return signature;
  }
  /**
   * 统一处理报错
   */
  handleError(error) {
    switch (error.code) {
      case "APPID_MCHID_NOT_MATCH":
        throw new APPID_MCHID_NOT_MATCH(error.message);
      case "INVALID_REQUEST":
        throw new INVALID_REQUEST(error.message);
      case "SIGN_ERROR":
        throw new SIGN_ERROR(error.message);
      case "MCH_NOT_EXISTS":
        throw new MCH_NOT_EXISTS(error.message);
      case "ORDER_CLOSED":
        throw new ORDER_CLOSED(error.message);
      case "ACCOUNT_ERROR":
        throw new ACCOUNT_ERROR(error.message);
      case "NO_AUTH":
        throw new NO_AUTH(error.message);
      case "NOT_ENOUGH":
        throw new NOT_ENOUGH(error.message);
      case "OUT_TRADE_NO_USED":
        throw new OUT_TRADE_NO_USED(error.message);
      case "RULE_LIMIT":
        throw new RULE_LIMIT(error.message);
      case "TRADE_ERROR":
        throw new TRADE_ERROR(error.message);
      case "ORDER_NOT_EXIST":
        throw new ORDER_NOT_EXIST(error.message);
      case "FREQUENCY_LIMITED":
        throw new FREQUENCY_LIMITED(error.message);
      case "BANK_ERROR":
        throw new BANK_ERROR(error.message);
      case "INVALID_TRANSACTIONID":
        throw new INVALID_TRANSACTIONID(error.message);
      case "OPENID_MISMATCH":
        throw new OPENID_MISMATCH(error.message);
      case "SYSTEM_ERROR":
        throw new SYSTEM_ERROR(error.message);
      case "PARAM_ERROR":
        throw new PARAM_ERROR(error.message);
      default:
        throw new Error(error.message);
    }
  }
  /**
   * 构建请求
   */
  async buildResponse(data) {
    const signature = data ? this.getSignature(JSON.stringify(data)) : this.getSignature();
    const Authorization = `${this.SCHEMA} mchid="${this.options.mchid}",nonce_str="${this.NONCE_STR}",signature="${signature}",timestamp="${this.TIMESTAMP}",serial_no="${this.options.serial_no}"`;
    const headersInit = {
      "Content-Type": "application/json",
      "Authorization": Authorization,
      "Accept": "application/json",
      "User-Agent": "127.0.0.1"
    };
    const headers = new Headers(headersInit);
    return fetch(`${this.PRIMARY_DOMAIN + this.URL}`, {
      body: JSON.stringify(data),
      headers,
      method: this.METHOD
    });
  }
  /**
   * 构建查询参数
   */
  buildQueryString(params) {
    return Object.entries(params).map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`).join("&");
  }
  /**
   * JSAPI / 小程序 下单
   */
  async createJsapiOrder(order) {
    await this.init("POST" /* POST */, "/v3/pay/transactions/jsapi");
    const response = await this.buildResponse({
      appid: this.options.appid,
      mchid: this.options.mchid,
      ...order
    });
    const data = await response.json();
    if (!response.ok) {
      this.handleError(data);
    }
    return data;
  }
  /**
   * h5 下单
   */
  async createH5Order(order) {
    await this.init("POST" /* POST */, "/v3/pay/transactions/h5");
    const response = await this.buildResponse({
      appid: this.options.appid,
      mchid: this.options.mchid,
      ...order
    });
    const data = await response.json();
    if (!response.ok) {
      this.handleError(data);
    }
    return data;
  }
  /**
   * native 下单
   */
  async createNativeOrder(order) {
    await this.init("POST" /* POST */, "/v3/pay/transactions/native");
    const response = await this.buildResponse({
      appid: this.options.appid,
      mchid: this.options.mchid,
      ...order
    });
    const data = await response.json();
    if (!response.ok) {
      this.handleError(data);
    }
    return data;
  }
  /**
   * App 下单
   */
  async createAppOrder(order) {
    await this.init("POST" /* POST */, "/v3/pay/transactions/app");
    const response = await this.buildResponse({
      appid: this.options.appid,
      mchid: this.options.mchid,
      ...order
    });
    const data = await response.json();
    if (!response.ok) {
      this.handleError(data);
    }
    return data;
  }
  /**
   * 获取平台证书
   */
  async getCertificates() {
    await this.init("GET" /* GET */, "/v3/certificates");
    const response = await this.buildResponse();
    const data = await response.json();
    if (!response.ok) {
      this.handleError(data);
    }
    const { data: result } = data;
    return result;
  }
  /**
   * 签名验证 apiv3
   */
  async verifySign(options) {
    const signatureStr = `${options.timestamp}
${options.nonce_str}
${options.requestBody}
`;
    let certificate = this.certificates.find((c) => c.serial_no === options.serial_no);
    if (!certificate) {
      await this.getCertificates();
    }
    certificate = this.certificates.find((c) => c.serial_no === options.serial_no);
    if (!certificate) {
      throw new SIGN_ERROR();
    }
    const publicKey = certificate.encrypt_certificate.ciphertext;
    const verify = crypto.createVerify("RSA-SHA256").update(signatureStr).verify(publicKey, options.signature, "base64");
    return verify;
  }
  /**
   * 微信支付订单号查询订单
   */
  async queryOrderByTransactionId(transactionId) {
    await this.init("GET" /* GET */, `/v3/pay/transactions/id/${transactionId}?mchid=${this.options.mchid}`);
    const response = await this.buildResponse();
    const data = await response.json();
    if (!response.ok) {
      this.handleError(data);
    }
    return data;
  }
  /**
   * 商户订单号查询订单
   */
  async queryOrderByOutTradeNo(out_trade_no) {
    await this.init("GET" /* GET */, `/v3/pay/transactions/out-trade-no/${out_trade_no}?mchid=${this.options.mchid}`);
    const response = await this.buildResponse();
    const data = await response.json();
    if (!response.ok) {
      this.handleError(data);
    }
    return data;
  }
  /**
   * 关闭订单
   */
  async closeOrder(out_trade_no) {
    await this.init("POST" /* POST */, `/v3/pay/transactions/out-trade-no/${out_trade_no}/close`);
    const mchid = this.options.mchid;
    const response = await this.buildResponse({ mchid });
    const data = await response.json();
    if (!response.ok) {
      this.handleError(data);
    }
  }
  /**
   * 通过商户订单号退款
   */
  async refundByOutTradeNo(options) {
    await this.init("POST" /* POST */, "/v3/refund/domestic/refunds");
    const response = await this.buildResponse(options);
    const data = await response.json();
    if (!response.ok) {
      this.handleError(data);
    }
    return data;
  }
  /**
   * 通过微信支付订单号退款
   */
  async refundByTransactionId(options) {
    await this.init("POST" /* POST */, "/v3/refund/domestic/refunds");
    const response = await this.buildResponse(options);
    const data = await response.json();
    if (!response.ok) {
      this.handleError(data);
    }
    return data;
  }
  /**
   * 查询单笔退款（通过商户退款单号）
   */
  async getRefundByOutRefundNo(out_refund_no) {
    await this.init("GET" /* GET */, `/v3/refund/domestic/refunds/${out_refund_no}`);
    const response = await this.buildResponse();
    const data = await response.json();
    if (!response.ok) {
      this.handleError(data);
    }
    return data;
  }
  /**
   * 申请交易账单
   */
  async getTradeBill(options) {
    await this.init("GET" /* GET */, `/v3/bill/tradebill?${this.buildQueryString(options)}`);
    const response = await this.buildResponse();
    const data = await response.json();
    if (!response.ok) {
      this.handleError(data);
    }
    return data;
  }
  /**
   * 申请资金帐单
   */
  async getFundFlowBill(options) {
    await this.init("GET" /* GET */, `/v3/bill/fundflowbill?${this.buildQueryString(options)}`);
    const response = await this.buildResponse();
    const data = await response.json();
    if (!response.ok) {
      this.handleError(data);
    }
    return data;
  }
  /**
   * 支付回调参数解密
   */
  async decryptPayCallback(options) {
    const { nonce, associated_data, ciphertext } = options;
    const _ciphertext = Buffer.from(ciphertext, "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", this.options.apiv3Key, nonce);
    decipher.setAAD(Buffer.from(associated_data));
    decipher.setAuthTag(_ciphertext.subarray(_ciphertext.length - 16));
    const decrypted = decipher.update(_ciphertext.subarray(0, _ciphertext.length - 16), null, "utf8");
    try {
      return JSON.parse(decrypted);
    } catch (err) {
      return decrypted;
    }
  }
};
WechatService = __decorateClass([
  Injectable(),
  __decorateParam(0, Inject("WECHAT_OPTIONS"))
], WechatService);

// src/module.ts
var WechatModule = class {
  static register(options) {
    return {
      global: true,
      module: WechatModule,
      exports: [WechatService],
      providers: [
        {
          provide: "WECHAT_OPTIONS",
          useValue: options
        },
        WechatService
      ]
    };
  }
};
WechatModule = __decorateClass([
  Module({})
], WechatModule);
export {
  ACCOUNT_ERROR,
  APPID_MCHID_NOT_MATCH,
  AllowMethod,
  BANK_ERROR,
  BaseService,
  FREQUENCY_LIMITED,
  INVALID_REQUEST,
  INVALID_TRANSACTIONID,
  MCH_NOT_EXISTS,
  NOT_ENOUGH,
  NO_AUTH,
  OPENID_MISMATCH,
  ORDER_CLOSED,
  ORDER_NOT_EXIST,
  OUT_TRADE_NO_USED,
  PARAM_ERROR,
  RULE_LIMIT,
  SIGN_ERROR,
  SYSTEM_ERROR,
  TRADE_ERROR,
  WechatModule,
  WechatService
};

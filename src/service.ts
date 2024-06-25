import { Injectable, Inject } from '@nestjs/common'
import fetch, { Headers } from 'node-fetch'
import * as crypto from 'crypto'
import { ACCOUNT_ERROR, APPID_MCHID_NOT_MATCH, BANK_ERROR, FREQUENCY_LIMITED, INVALID_REQUEST, INVALID_TRANSACTIONID, MCH_NOT_EXISTS, NO_AUTH, NOT_ENOUGH, OPENID_MISMATCH, ORDER_CLOSED, ORDER_NOT_EXIST, OUT_TRADE_NO_USED, PARAM_ERROR, RULE_LIMIT, SIGN_ERROR, SYSTEM_ERROR, TRADE_ERROR } from './error'
import { AllowMethod, BaseService, FundFlowBillOptions, RefundByOutTradeNoOptions, RefundByTransactionIdOptions, RefundResponse, TradeBillOptions, BillResponse, CertificatesResponse, H5Order, H5OrderResponse, JsapiOrder, JsapiOrderResponse, NativeOrder, NativeOrderResponse, Order, ResponseError, VerifySignOptions, WechatOptions, AppOrder, AppOrderResponse, DecryptPayCallbackOptions } from './types'

@Injectable()
export class WechatService extends BaseService {
  protected URL = ''
  protected TIMESTAMP = 0
  protected NONCE_STR = ''
  protected options: WechatOptions
  protected METHOD = AllowMethod.GET
  protected SCHEMA = 'WECHATPAY2-SHA256-RSA2048' as const
  protected PRIMARY_DOMAIN = 'https://api.mch.weixin.qq.com' as const
  protected certificates: CertificatesResponse[] = []

  constructor(@Inject('WECHAT_OPTIONS') options: WechatOptions) {
    super()
    this.options = options
    this.init(AllowMethod.GET, '')
    this.getCertificates().then((certificates) => {
      this.certificates = certificates
    })
  }

  /**
   * 初始化 请求方法、请求地址、时间戳和随机字符串
   */
  private async init(method: AllowMethod, url: string) {
    this.METHOD = method
    this.URL = url
    this.TIMESTAMP = this.getTimestamp()
    this.NONCE_STR = this.generateNonceStr()
  }

  /**
   * 生成32位随机字符串，包含数字、大写字母
   */
  private generateNonceStr() {
    return crypto.randomBytes(32).toString('hex').substring(0, 32).toUpperCase()
  }

  /**
   * 格林威治时间1970年01月01日00时00分00秒(北京时间1970年01月01日08时00分00秒)起至现在的总秒数
   */
  private getTimestamp() {
    return Math.floor(new Date().getTime() / 1000)
  }

  /**
   * 获取签名值
   */
  public getSignature(requetBody = '') {
    const data = `${this.METHOD}\n${this.URL}\n${this.TIMESTAMP}\n${this.NONCE_STR}\n${requetBody}\n`
    const signature = crypto.createSign('RSA-SHA256').update(data).sign(this.options.privateKey, 'base64')
    return signature
  }

  /**
   * 统一处理报错
   */
  private handleError(error: ResponseError): never {
    switch (error.code) {
      case 'APPID_MCHID_NOT_MATCH':
        throw new APPID_MCHID_NOT_MATCH(error.message)
      case 'INVALID_REQUEST':
        throw new INVALID_REQUEST(error.message)
      case 'SIGN_ERROR':
        throw new SIGN_ERROR(error.message)
      case 'MCH_NOT_EXISTS':
        throw new MCH_NOT_EXISTS(error.message)
      case 'ORDER_CLOSED':
        throw new ORDER_CLOSED(error.message)
      case 'ACCOUNT_ERROR':
        throw new ACCOUNT_ERROR(error.message)
      case 'NO_AUTH':
        throw new NO_AUTH(error.message)
      case 'NOT_ENOUGH':
        throw new NOT_ENOUGH(error.message)
      case 'OUT_TRADE_NO_USED':
        throw new OUT_TRADE_NO_USED(error.message)
      case 'RULE_LIMIT':
        throw new RULE_LIMIT(error.message)
      case 'TRADE_ERROR':
        throw new TRADE_ERROR(error.message)
      case 'ORDER_NOT_EXIST':
        throw new ORDER_NOT_EXIST(error.message)
      case 'FREQUENCY_LIMITED':
        throw new FREQUENCY_LIMITED(error.message)
      case 'BANK_ERROR':
        throw new BANK_ERROR(error.message)
      case 'INVALID_TRANSACTIONID':
        throw new INVALID_TRANSACTIONID(error.message)
      case 'OPENID_MISMATCH':
        throw new OPENID_MISMATCH(error.message)
      case 'SYSTEM_ERROR':
        throw new SYSTEM_ERROR(error.message)
      case 'PARAM_ERROR':
        throw new PARAM_ERROR(error.message)
      default :
        throw new Error(error.message)
    }
  }

  /**
   * 构建请求
   */
  private async buildResponse<T>(data?:T) {
    const signature = data ? this.getSignature(JSON.stringify(data)) : this.getSignature()
    const Authorization = `${this.SCHEMA} mchid="${this.options.mchid}",nonce_str="${this.NONCE_STR}",signature="${signature}",timestamp="${this.TIMESTAMP}",serial_no="${this.options.serial_no}"`
    const headersInit = {
      'Content-Type': 'application/json',
      'Authorization': Authorization,
      'Accept': 'application/json',
      'User-Agent': '127.0.0.1'
    }
    const headers = new Headers(headersInit)
    return fetch(`${this.PRIMARY_DOMAIN + this.URL}`, {
      body: JSON.stringify(data),
      headers,
      method: this.METHOD
    })
  }

  /**
   * 构建查询参数
   */
  private buildQueryString<T extends object>(params: T): string {
    return Object.entries(params)
      .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value!)}`)
      .join('&')
  }

  /**
   * JSAPI / 小程序 下单
   */
  public async createJsapiOrder(order: JsapiOrder) {
    await this.init(AllowMethod.POST, '/v3/pay/transactions/jsapi')
    const response = await this.buildResponse({
      appid: this.options.appid,
      mchid: this.options.mchid,
      ...order
    })
    const data = await response.json()
    if (!response.ok) {
      this.handleError(data as ResponseError)
    }
    return data as Promise<JsapiOrderResponse>
  }

  /**
   * h5 下单
   */
  public async createH5Order(order: H5Order) {
    await this.init(AllowMethod.POST, '/v3/pay/transactions/h5')
    const response = await this.buildResponse({
      appid: this.options.appid,
      mchid: this.options.mchid,
      ...order
    })
    const data = await response.json()
    if (!response.ok) {
      this.handleError(data as ResponseError)
    }
    return data as Promise<H5OrderResponse>
  }

  /**
   * native 下单
   */
  public async createNativeOrder(order: NativeOrder) {
    await this.init(AllowMethod.POST, '/v3/pay/transactions/native')
    const response = await this.buildResponse({
      appid: this.options.appid,
      mchid: this.options.mchid,
      ...order
    })
    const data = await response.json()
    if (!response.ok) {
      this.handleError(data as ResponseError)
    }
    return data as Promise<NativeOrderResponse>
  }

  /**
   * App 下单
   */
  public async createAppOrder(order: AppOrder) {
    await this.init(AllowMethod.POST, '/v3/pay/transactions/app')
    const response = await this.buildResponse({
      appid: this.options.appid,
      mchid: this.options.mchid,
      ...order
    })
    const data = await response.json()
    if (!response.ok) {
      this.handleError(data as ResponseError)
    }
    return data as AppOrderResponse
  }

  /**
   * 获取平台证书
   */
  public async getCertificates() {
    await this.init(AllowMethod.GET, '/v3/certificates')
    const response = await this.buildResponse()
    const data = await response.json()
    if (!response.ok) {
      this.handleError(data as ResponseError)
    }
    const { data: result } = data as { data: CertificatesResponse[] }
    return result as CertificatesResponse[]
  }

  /**
   * 签名验证 apiv3
   */
  public async verifySign(options: VerifySignOptions) {
    const signatureStr = `${options.timestamp}\n${options.nonce_str}\n${options.requestBody}\n`
    let certificate = this.certificates.find(c => c.serial_no === this.options.serial_no)
    if (!certificate) {
      await this.getCertificates()
    }
    certificate = this.certificates.find(c => c.serial_no === this.options.serial_no)
    if (!certificate) {
      throw new SIGN_ERROR()
    }
    const publicKey = certificate.encrypt_certificate.ciphertext
    const verify = crypto.createVerify('RSA-SHA256').update(signatureStr).verify(publicKey, options.signature, 'base64')
    return verify
  }

  /**
   * 微信支付订单号查询订单
   */
  public async queryOrderByTransactionId(transactionId: string) {
    await this.init(AllowMethod.GET, `/v3/pay/transactions/id/${transactionId}?mchid=${this.options.mchid}`)
    const response = await this.buildResponse()
    const data = await response.json()
    if (!response.ok) {
      this.handleError(data as ResponseError)
    }
    return data as Order
  }

  /**
   * 商户订单号查询订单
   */
  public async queryOrderByOutTradeNo(out_trade_no: string) {
    await this.init(AllowMethod.GET, `/v3/pay/transactions/out-trade-no/${out_trade_no}?mchid=${this.options.mchid}`)
    const response = await this.buildResponse()
    const data = await response.json()
    if (!response.ok) {
      this.handleError(data as ResponseError)
    }
    return data as Order
  }

  /**
   * 关闭订单
   */
  public async closeOrder(out_trade_no: string) {
    await this.init(AllowMethod.POST, `/v3/pay/transactions/out-trade-no/${out_trade_no}/close`)
    const mchid = this.options.mchid
    const response = await this.buildResponse({ mchid })
    const data = await response.json()
    if (!response.ok) {
      this.handleError(data as ResponseError)
    }
  }

  /**
   * 通过商户订单号退款
   */
  public async refundByOutTradeNo(options: RefundByOutTradeNoOptions) {
    await this.init(AllowMethod.POST, '/v3/refund/domestic/refunds')
    const response = await this.buildResponse(options)
    const data = await response.json()
    if (!response.ok) {
      this.handleError(data as ResponseError)
    }
    return data as RefundResponse
  }

  /**
   * 通过微信支付订单号退款
   */
  public async refundByTransactionId(options: RefundByTransactionIdOptions) {
    await this.init(AllowMethod.POST, '/v3/refund/domestic/refunds')
    const response = await this.buildResponse(options)
    const data = await response.json()
    if (!response.ok) {
      this.handleError(data as ResponseError)
    }
    return data as RefundResponse
  }

  /**
   * 查询单笔退款（通过商户退款单号）
   */
  public async getRefundByOutRefundNo(out_refund_no: string) {
    await this.init(AllowMethod.GET, `/v3/refund/domestic/refunds/${out_refund_no}`)
    const response = await this.buildResponse()
    const data = await response.json()
    if (!response.ok) {
      this.handleError(data as ResponseError)
    }
    return data as RefundResponse
  }

  /**
   * 申请交易账单
   */
  public async getTradeBill(options: TradeBillOptions) {
    await this.init(AllowMethod.GET, `/v3/bill/tradebill?${this.buildQueryString(options)}`)
    const response = await this.buildResponse()
    const data = await response.json()
    if (!response.ok) {
      this.handleError(data as ResponseError)
    }
    return data as BillResponse
  }

  /**
   * 申请资金帐单
   */
  public async getFundFlowBill(options: FundFlowBillOptions) {
    await this.init(AllowMethod.GET, `/v3/bill/fundflowbill?${this.buildQueryString(options)}`)
    const response = await this.buildResponse()
    const data = await response.json()
    if (!response.ok) {
      this.handleError(data as ResponseError)
    }
    return data as BillResponse
  }

  /**
   * 支付回调参数解密
   */
  public async decryptPayCallback<T extends unknown>(options: DecryptPayCallbackOptions) {
    const { nonce, associated_data, ciphertext } = options
    const _ciphertext = Buffer.from(ciphertext, 'base64')
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.options.apiv3Key, nonce)
    decipher.setAAD(Buffer.from(associated_data))
    decipher.setAuthTag(_ciphertext.subarray(_ciphertext.length - 16))
    const decrypted = decipher.update(_ciphertext.subarray(0, _ciphertext.length - 16), null, 'utf8')
    try {
      return JSON.parse(decrypted) as T
    } catch (err) {
      return decrypted as T
    }
  }
}
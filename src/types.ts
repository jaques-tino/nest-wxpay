export interface FundsFromItem {
  account: 'AVAILABLE' | 'UNAVAILABLE'
  amount: number
}

export interface AmountReq {
  refund: number
  from?: FundsFromItem[]
  total: number
  currency: string
}

export interface RefundOptions {
  out_refund_no: string
  reason?: string
  notify_url?: string
  funds_account?: string
  amount: AmountReq
  goods_detail?: (Omit<GoodsDetail, 'quantity'> & { refund_amount: number; refund_quantity: number })[]
}

export interface RefundByOutTradeNoOptions extends RefundOptions {
  out_trade_no: string
}

export interface RefundByTransactionIdOptions extends RefundOptions {
  transaction_id: string
}

export interface Amount {
  total: number
  refund: number
  from?: FundsFromItem[]
  payer_total: number
  payer_refund: number
  settlement_refund: number
  settlement_total: number
  discount_refund: number
  currency: string
  refund_fee?: number
}

export interface Promotion {
  promotion_id: string
  scope: 'GLOBAL' | 'SINGLE'
  type: 'COUPON' | 'DISCOUNT'
  amount: number
  refund_amount: number
  goods_detail?: (Omit<GoodsDetail, 'quantity'> & { refund_amount: number; refund_quantity: number })[]
}

export interface RefundResponse {
  refund_id: string
  out_refund_no: string
  transaction_id: string
  out_trade_no: string
  channel: 'ORIGINAL' | 'BALANCE' | 'OTHER_BALANCE' | 'OTHER_BANKCARD'
  user_received_account: string
  success_time?: string
  create_time: string
  status: 'SUCCESS' | 'CLOSED' | 'PROCESSING' | 'ABNORMAL'
  funds_account?: 'UNSETTLED' | 'AVAILABLE' | 'UNAVAILABLE' | 'OPERATION' | 'BASIC' | 'ECNY_BASIC'
  amount: Amount
  promotion_detail?: Promotion[]
}

export const enum AllowMethod {
  GET = 'GET',
  POST = 'POST',
  PUT = 'PUT',
  DELETE = 'DELETE',
  PATCH = 'PATCH'
}

export abstract class BaseService {
  protected abstract METHOD: AllowMethod
  protected abstract URL: string
  protected abstract TIMESTAMP: number
  protected abstract NONCE_STR: string
  protected abstract SCHEMA: 'WECHATPAY2-SHA256-RSA2048'
  protected abstract PRIMARY_DOMAIN: 'https://api.mch.weixin.qq.com' | 'https://api2.mch.weixin.qq.com'
  protected abstract options: WechatOptions
}

export interface TradeBillOptions {
  bill_date: string
  bill_type?: 'ALL' | 'SUCCESS' | 'REFUND' | 'RECHARGE_REFUND' | 'ALL_SPECIAL' | 'SUC_SPECIAL' | 'REF_SPECIAL'
  tar_type?: 'GZIP'
}

export interface BillResponse {
  hash_type: 'SHA1'
  hash_value: string
  download_url: string
}

export interface FundFlowBillOptions {
  bill_date: string
  account_type?: 'BASIC' | 'OPERATION' | 'FEES' | 'ALL'
  tar_type?: 'GZIP'
}

export interface WechatOptions {
  appid: string
  mchid: string
  serial_no: string
  privateKey: Buffer
}

export interface VerifySignOptions {
  timestamp: number
  nonce_str: string
  requestBody: string
  signature: string
  serial_no: string
}

export interface EncryptCertificate {
  algorithm: string
  associated_data?: string
  ciphertext: string
  nonce: string
}

export interface CertificatesResponse {
  serial_no: string
  effective_time?: number
  expire_time?: number
  encrypt_certificate: EncryptCertificate
}

export interface CertificatesResponseFailDetail {
  field: string
  location: string
  detail: {
    issue: string
  }
  sign_information: {
    method: string
    sign_message_length: number
    truncated_sign_message: string
    url: string
  }
}

export interface ResponseError {
  code: string
  message: string
}

export interface CommReqAmountInfo {
  total: number
  currency?: string
}

export interface JsapiReqPayerInfo {
  openid: string
}

export interface GoodsDetail {
  merchant_goods_id: string
  wechatpay_goods_id?: string
  goods_name?: string
  quantity: number
  unit_price: number
}

export interface OrderDetail {
  cost_price?: number
  invoice_id?: string
  goods_detail: GoodsDetail
}

export interface StoreInfo {
  id: string
  name?: string
  area_code?: string
  address?: string
}

export interface CommReqSceneInfo {
  payer_client_ip: string
  device_id?: string
  store_info?: StoreInfo
}

export interface SettleInfo {
  profit_sharing?: boolean
}

export interface JsapiOrder {
  description: string
  out_trade_no: string
  time_expire?: string
  attach?: string
  notify_url: string
  goods_tag?: string
  support_fapiao?: boolean
  amount: CommReqAmountInfo
  payer: JsapiReqPayerInfo
  detail?: OrderDetail
  scene_info?: CommReqSceneInfo
  settle_info?: SettleInfo
}

export type H5Order = Omit<JsapiOrder, 'payer'> & { detail: Partial<OrderDetail>, scene_info: CommReqSceneInfo }

export type NativeOrder = Omit<JsapiOrder, 'payer'> & { detail: Partial<OrderDetail> }

export type AppOrder = JsapiOrder

export interface JsapiOrderResponse {
  prepay_id: string
}

export interface H5OrderResponse {
  h5_url: string
}

export interface NativeOrderResponse {
  code_url: string
}

export interface AppOrderResponse {
  prepay_id: string
}

export interface CommRespPayerInfo {
  openid?: string
}

export interface CommRespAmountInfo {
  total?: number
  payer_total?: number
  currency?: string
  payer_currency?: string
}

export interface CommRespSceneInfo {
  device_id?: string
}

export interface GoodsDetailInPromotion {
  goods_id: string
  quantity: number
  unit_price: number
  discount_amount: number
  goods_remark?: string
}

export interface PromotionDetail {
  coupon_id: string
  name?: string
  scope?: 'GLOBAL' | 'SINGLE'
  type?: 'CASH' | 'NOCASH'
  amount: number
  stock_id?: string
  wechatpay_contribute?: number
  merchant_contribute?: number
  other_contribute?: number
  currency?: string
  goods_detail?: GoodsDetailInPromotion[]
}

export interface Order {
  appid: string
  machid: string
  out_trade_no: string
  transaction_id?: string
  trade_type?: 'JSAPI' | 'NATIVE' | 'APP' | 'MICROPAY' | 'MWEB' | 'FACEPAY'
  trade_state: 'SUCCESS' | 'REFUND' | 'NOTPAY' | 'CLOSED' | 'REVOKED' | 'USERPAYING' | 'PAYERROR'
  trade_state_desc: string
  bank_type?: string
  attach?: string
  success_time?: string
  payer?: CommRespPayerInfo
  amount?: CommRespAmountInfo
  scene_info?: CommRespSceneInfo
  promotion_detail?: PromotionDetail[]
}

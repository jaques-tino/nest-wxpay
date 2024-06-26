import { DynamicModule } from '@nestjs/common';

interface FundsFromItem {
    account: 'AVAILABLE' | 'UNAVAILABLE';
    amount: number;
}
interface AmountReq {
    refund: number;
    from?: FundsFromItem[];
    total: number;
    currency: string;
}
interface RefundOptions {
    out_refund_no: string;
    reason?: string;
    notify_url?: string;
    funds_account?: string;
    amount: AmountReq;
    goods_detail?: (Omit<GoodsDetail, 'quantity'> & {
        refund_amount: number;
        refund_quantity: number;
    })[];
}
interface RefundByOutTradeNoOptions extends RefundOptions {
    out_trade_no: string;
}
interface RefundByTransactionIdOptions extends RefundOptions {
    transaction_id: string;
}
interface Amount {
    total: number;
    refund: number;
    from?: FundsFromItem[];
    payer_total: number;
    payer_refund: number;
    settlement_refund: number;
    settlement_total: number;
    discount_refund: number;
    currency: string;
    refund_fee?: number;
}
interface Promotion {
    promotion_id: string;
    scope: 'GLOBAL' | 'SINGLE';
    type: 'COUPON' | 'DISCOUNT';
    amount: number;
    refund_amount: number;
    goods_detail?: (Omit<GoodsDetail, 'quantity'> & {
        refund_amount: number;
        refund_quantity: number;
    })[];
}
interface RefundResponse {
    refund_id: string;
    out_refund_no: string;
    transaction_id: string;
    out_trade_no: string;
    channel: 'ORIGINAL' | 'BALANCE' | 'OTHER_BALANCE' | 'OTHER_BANKCARD';
    user_received_account: string;
    success_time?: string;
    create_time: string;
    status: 'SUCCESS' | 'CLOSED' | 'PROCESSING' | 'ABNORMAL';
    funds_account?: 'UNSETTLED' | 'AVAILABLE' | 'UNAVAILABLE' | 'OPERATION' | 'BASIC' | 'ECNY_BASIC';
    amount: Amount;
    promotion_detail?: Promotion[];
}
declare const enum AllowMethod {
    GET = "GET",
    POST = "POST",
    PUT = "PUT",
    DELETE = "DELETE",
    PATCH = "PATCH"
}
declare abstract class BaseService {
    protected abstract METHOD: AllowMethod;
    protected abstract URL: string;
    protected abstract TIMESTAMP: number;
    protected abstract NONCE_STR: string;
    protected abstract SCHEMA: 'WECHATPAY2-SHA256-RSA2048';
    protected abstract PRIMARY_DOMAIN: 'https://api.mch.weixin.qq.com' | 'https://api2.mch.weixin.qq.com';
    protected abstract options: WechatOptions;
}
interface TradeBillOptions {
    bill_date: string;
    bill_type?: 'ALL' | 'SUCCESS' | 'REFUND' | 'RECHARGE_REFUND' | 'ALL_SPECIAL' | 'SUC_SPECIAL' | 'REF_SPECIAL';
    tar_type?: 'GZIP';
}
interface BillResponse {
    hash_type: 'SHA1';
    hash_value: string;
    download_url: string;
}
interface FundFlowBillOptions {
    bill_date: string;
    account_type?: 'BASIC' | 'OPERATION' | 'FEES' | 'ALL';
    tar_type?: 'GZIP';
}
interface WechatOptions {
    appid: string;
    mchid: string;
    serial_no: string;
    privateKey: Buffer;
    apiv3Key: string;
}
interface VerifySignOptions {
    timestamp: number;
    nonce_str: string;
    requestBody: string;
    signature: string;
    serial_no: string;
}
interface EncryptCertificate {
    algorithm: string;
    associated_data?: string;
    ciphertext: string;
    nonce: string;
}
interface CertificatesResponse {
    serial_no: string;
    effective_time?: number;
    expire_time?: number;
    encrypt_certificate: EncryptCertificate;
}
interface CertificatesResponseFailDetail {
    field: string;
    location: string;
    detail: {
        issue: string;
    };
    sign_information: {
        method: string;
        sign_message_length: number;
        truncated_sign_message: string;
        url: string;
    };
}
interface ResponseError {
    code: string;
    message: string;
}
interface CommReqAmountInfo {
    total: number;
    currency?: string;
}
interface JsapiReqPayerInfo {
    openid: string;
}
interface GoodsDetail {
    merchant_goods_id: string;
    wechatpay_goods_id?: string;
    goods_name?: string;
    quantity: number;
    unit_price: number;
}
interface OrderDetail {
    cost_price?: number;
    invoice_id?: string;
    goods_detail: GoodsDetail;
}
interface StoreInfo {
    id: string;
    name?: string;
    area_code?: string;
    address?: string;
}
interface CommReqSceneInfo {
    payer_client_ip: string;
    device_id?: string;
    store_info?: StoreInfo;
}
interface SettleInfo {
    profit_sharing?: boolean;
}
interface JsapiOrder {
    description: string;
    out_trade_no: string;
    time_expire?: string;
    attach?: string;
    notify_url: string;
    goods_tag?: string;
    support_fapiao?: boolean;
    amount: CommReqAmountInfo;
    payer: JsapiReqPayerInfo;
    detail?: OrderDetail;
    scene_info?: CommReqSceneInfo;
    settle_info?: SettleInfo;
}
type H5Order = Omit<JsapiOrder, 'payer'> & {
    detail: Partial<OrderDetail>;
    scene_info: CommReqSceneInfo;
};
type NativeOrder = Omit<JsapiOrder, 'payer'> & {
    detail: Partial<OrderDetail>;
};
type AppOrder = JsapiOrder;
interface JsapiOrderResponse {
    prepay_id: string;
}
interface H5OrderResponse {
    h5_url: string;
}
interface NativeOrderResponse {
    code_url: string;
}
interface AppOrderResponse {
    prepay_id: string;
}
interface CommRespPayerInfo {
    openid?: string;
}
interface CommRespAmountInfo {
    total?: number;
    payer_total?: number;
    currency?: string;
    payer_currency?: string;
}
interface CommRespSceneInfo {
    device_id?: string;
}
interface GoodsDetailInPromotion {
    goods_id: string;
    quantity: number;
    unit_price: number;
    discount_amount: number;
    goods_remark?: string;
}
interface PromotionDetail {
    coupon_id: string;
    name?: string;
    scope?: 'GLOBAL' | 'SINGLE';
    type?: 'CASH' | 'NOCASH';
    amount: number;
    stock_id?: string;
    wechatpay_contribute?: number;
    merchant_contribute?: number;
    other_contribute?: number;
    currency?: string;
    goods_detail?: GoodsDetailInPromotion[];
}
interface Order {
    appid: string;
    machid: string;
    out_trade_no: string;
    transaction_id?: string;
    trade_type?: 'JSAPI' | 'NATIVE' | 'APP' | 'MICROPAY' | 'MWEB' | 'FACEPAY';
    trade_state: 'SUCCESS' | 'REFUND' | 'NOTPAY' | 'CLOSED' | 'REVOKED' | 'USERPAYING' | 'PAYERROR';
    trade_state_desc: string;
    bank_type?: string;
    attach?: string;
    success_time?: string;
    payer?: CommRespPayerInfo;
    amount?: CommRespAmountInfo;
    scene_info?: CommRespSceneInfo;
    promotion_detail?: PromotionDetail[];
}
interface DecryptPayCallbackOptions {
    ciphertext: string;
    associated_data: string;
    nonce: string;
}

declare class WechatModule {
    static register(options: WechatOptions): DynamicModule;
}

declare class WechatService extends BaseService {
    protected URL: string;
    protected TIMESTAMP: number;
    protected NONCE_STR: string;
    protected options: WechatOptions;
    protected METHOD: AllowMethod;
    protected SCHEMA: "WECHATPAY2-SHA256-RSA2048";
    protected PRIMARY_DOMAIN: "https://api.mch.weixin.qq.com";
    protected certificates: CertificatesResponse[];
    constructor(options: WechatOptions);
    private init;
    private generateNonceStr;
    private getTimestamp;
    getSignature(requetBody?: string): string;
    private handleError;
    private buildResponse;
    private buildQueryString;
    createJsapiOrder(order: JsapiOrder): Promise<JsapiOrderResponse>;
    createH5Order(order: H5Order): Promise<H5OrderResponse>;
    createNativeOrder(order: NativeOrder): Promise<NativeOrderResponse>;
    createAppOrder(order: AppOrder): Promise<AppOrderResponse>;
    getCertificates(): Promise<CertificatesResponse[]>;
    verifySign(options: VerifySignOptions): Promise<boolean>;
    queryOrderByTransactionId(transactionId: string): Promise<Order>;
    queryOrderByOutTradeNo(out_trade_no: string): Promise<Order>;
    closeOrder(out_trade_no: string): Promise<void>;
    refundByOutTradeNo(options: RefundByOutTradeNoOptions): Promise<RefundResponse>;
    refundByTransactionId(options: RefundByTransactionIdOptions): Promise<RefundResponse>;
    getRefundByOutRefundNo(out_refund_no: string): Promise<RefundResponse>;
    getTradeBill(options: TradeBillOptions): Promise<BillResponse>;
    getFundFlowBill(options: FundFlowBillOptions): Promise<BillResponse>;
    decryptPayCallback<T extends unknown>(options: DecryptPayCallbackOptions): Promise<T>;
}

declare class PARAM_ERROR extends Error {
    name: string;
    constructor(message?: string);
}
declare class INVALID_REQUEST extends Error {
    name: string;
    constructor(message?: string);
}
declare class SIGN_ERROR extends Error {
    name: string;
    constructor(message?: string);
}
declare class APPID_MCHID_NOT_MATCH extends Error {
    name: string;
    constructor(message?: string);
}
declare class MCH_NOT_EXISTS extends Error {
    name: string;
    constructor(message?: string);
}
declare class ORDER_CLOSED extends Error {
    name: string;
    constructor(message?: string);
}
declare class ACCOUNT_ERROR extends Error {
    name: string;
    constructor(message?: string);
}
declare class NO_AUTH extends Error {
    name: string;
    constructor(message?: string);
}
declare class NOT_ENOUGH extends Error {
    name: string;
    constructor(message?: string);
}
declare class OUT_TRADE_NO_USED extends Error {
    name: string;
    constructor(message?: string);
}
declare class RULE_LIMIT extends Error {
    name: string;
    constructor(message?: string);
}
declare class TRADE_ERROR extends Error {
    name: string;
    constructor(message?: string);
}
declare class ORDER_NOT_EXIST extends Error {
    name: string;
    constructor(message?: string);
}
declare class FREQUENCY_LIMITED extends Error {
    name: string;
    constructor(message?: string);
}
declare class BANK_ERROR extends Error {
    name: string;
    constructor(message?: string);
}
declare class INVALID_TRANSACTIONID extends Error {
    name: string;
    constructor(message?: string);
}
declare class OPENID_MISMATCH extends Error {
    name: string;
    constructor(message?: string);
}
declare class SYSTEM_ERROR extends Error {
    name: string;
    constructor(message?: string);
}

export { ACCOUNT_ERROR, APPID_MCHID_NOT_MATCH, AllowMethod, type Amount, type AmountReq, type AppOrder, type AppOrderResponse, BANK_ERROR, BaseService, type BillResponse, type CertificatesResponse, type CertificatesResponseFailDetail, type CommReqAmountInfo, type CommReqSceneInfo, type CommRespAmountInfo, type CommRespPayerInfo, type CommRespSceneInfo, type DecryptPayCallbackOptions, type EncryptCertificate, FREQUENCY_LIMITED, type FundFlowBillOptions, type FundsFromItem, type GoodsDetail, type GoodsDetailInPromotion, type H5Order, type H5OrderResponse, INVALID_REQUEST, INVALID_TRANSACTIONID, type JsapiOrder, type JsapiOrderResponse, type JsapiReqPayerInfo, MCH_NOT_EXISTS, NOT_ENOUGH, NO_AUTH, type NativeOrder, type NativeOrderResponse, OPENID_MISMATCH, ORDER_CLOSED, ORDER_NOT_EXIST, OUT_TRADE_NO_USED, type Order, type OrderDetail, PARAM_ERROR, type Promotion, type PromotionDetail, RULE_LIMIT, type RefundByOutTradeNoOptions, type RefundByTransactionIdOptions, type RefundOptions, type RefundResponse, type ResponseError, SIGN_ERROR, SYSTEM_ERROR, type SettleInfo, type StoreInfo, TRADE_ERROR, type TradeBillOptions, type VerifySignOptions, WechatModule, type WechatOptions, WechatService };

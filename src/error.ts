export class PARAM_ERROR extends Error {
  name = 'PARAM_ERROR'
  constructor(message = '请根据错误提示正确传入参数') {
    super(`参数错误（${message}）`)
  }
}

export class INVALID_REQUEST extends Error {
  name = 'INVALID_REQUEST'
  constructor(message = '请参阅 接口规则：https://pay.weixin.qq.com/docs/merchant/development/interface-rules/basic-rules.html') {
    super(`HTTP 请求不符合微信支付 APIv3 接口规则（${message}）`)
  }
}

export class SIGN_ERROR extends Error {
  name = 'SIGN_ERROR'
  constructor(message = '请参阅 签名常见问题：https://pay.weixin.qq.com/docs/merchant/development/interface-rules/signature-faqs.html') {
    super(`验证不通过（${message}）`)
  }
}

export class APPID_MCHID_NOT_MATCH extends Error {
  name = 'APPID_MCHID_NOT_MATCH'
  constructor(message = '请确认AppID和mch_id是否匹配') {
    super(`appid和mchid不匹配（${message}）`)
  }
}

export class MCH_NOT_EXISTS extends Error {
  name = 'MCH_NOT_EXISTS'
  constructor(message = '请确认商户号是否正确') {
    super(`商户不存在（${message}）`)
  }
}

export class ORDER_CLOSED extends Error {
  name = 'ORDER_CLOSED'
  constructor(message = '当前订单已关闭，请重新下单') {
    super(`订单已关闭（${message}）`)
  }
}

export class ACCOUNT_ERROR extends Error {
  name = 'ACCOUNT_ERROR'
  constructor(message = '用户账号异常，无需更多操作') {
    super(`账号异常（${message}）`)
  }
}

export class NO_AUTH extends Error {
  name = 'NO_AUTH'
  constructor(message = '商户前往申请此接口相关权限') {
    super(`商户无权限（${message}）`)
  }
}

export class NOT_ENOUGH extends Error {
  name = 'NOT_ENOUGH'
  constructor(message = '用户账号余额不足，请用户充值或更换支付卡后再支付') {
    super(`余额不足（${message}）`)
  }
}

export class OUT_TRADE_NO_USED extends Error {
  name = 'OUT_TRADE_NO_USED'
  constructor(message = '请核实商户订单号是否重复提交') {
    super(`商户订单号重复（${message}）`)
  }
}

export class RULE_LIMIT extends Error {
  name = 'ORDER_CLOSED'
  constructor(message = '因业务规则限制请求频率，请查看接口返回的详细信息') {
    super(`业务规则限制（${message}）`)
  }
}

export class TRADE_ERROR extends Error {
  name = 'TRADE_ERROR'
  constructor(message = '因业务原因交易失败，请查看接口返回的详细信息') {
    super(`交易错误（${message}）`)
  }
}

export class ORDER_NOT_EXIST extends Error {
  name = 'ORDER_NOT_EXIST'
  constructor(message = '请检查订单是否发起过交易') {
    super(`订单不存在（${message}）`)
  }
}

export class FREQUENCY_LIMITED extends Error {
  name = 'FREQUENCY_LIMITED'
  constructor(message = '请降低请求接口频率') {
    super(`频率限制（${message}）`)
  }
}

export class BANK_ERROR extends Error {
  name = 'TRADE_NOT_EXIST'
  constructor(message = '银行系统异常，请用相同参数重新调用') {
    super(`银行系统异常（${message}）`)
  }
}

export class INVALID_TRANSACTIONID extends Error {
  name = 'INVALID_TRANSACTIONID'
  constructor(message = '请检查微信支付订单号是否正确') {
    super(`订单号非法（${message}）`)
  }
}

export class OPENID_MISMATCH extends Error {
  name = 'OPENID_MISMATCH'
  constructor(message = '请确认OpenID和AppID是否匹配') {
    super(`OpenID和AppID不匹配（${message}）`)
  }
}

export class SYSTEM_ERROR extends Error {
  name = 'SYSTEM_ERROR'
  constructor(message = '系统异常，请用相同参数重新调用') {
    super(`系统错误（${message}）`)
  }
}
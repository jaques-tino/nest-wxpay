import { WechatOptions } from './types'
import { DynamicModule, Module } from '@nestjs/common'
import { WechatService } from './service'

@Module({})
export class WechatModule {
  static register(options: WechatOptions): DynamicModule {
    return {
      global: true,
      module: WechatModule,
      exports: [WechatService],
      providers: [
        {
          provide: 'WECHAT_OPTIONS',
          useValue: options
        },
        WechatService
      ]
    }
  }
}

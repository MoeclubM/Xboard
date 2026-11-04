# Aerion 订阅适配器

Aerion/XBClient 使用独立的 `App\Protocols\Aerion` 适配器。订阅地址保留原有路径和令牌，使用 `flag=aerion` 或 `flag=xbclient` 选择；未指定 `flag` 时，也可通过 `User-Agent: Aerion` 或 `XBClient` 自动识别。

适配器输出 YAML，沿用现有 `clashmeta` 模板中的代理组、规则及标准协议字段。它独立维护支持的协议列表与能力过滤，不使用 Mihomo 的客户端版本要求。标准协议字段构造及模板渲染复用已有实现，避免维护两份相同代码。

Flux 只由 Aerion 适配器和 XBClient 专用节点接口导出。`flag=meta`、`flag=mihomo` 及其他 Mihomo 客户端标识始终选择原来的适配器；即使同时发送 `types=flux`、`X-XBClient-Protocols: flux` 或 Aerion 用户标识，也不会让 Mihomo 输出 Flux。

Aerion 适配器中的 `types` 明确列表优先于 `X-XBClient-Protocols`；列表未声明 Flux 时不输出 Flux。`types=all` 表示使用当前适配器支持的全部协议，不改变适配器选择。Flux 的字段序列化统一使用 `FluxConfig::toClientProxy()`，只输出客户端需要的入口与公开安全参数，排除监听地址、监听端口、证书路径、REALITY 私钥和回源地址。

XBClient 桌面端和安卓端订阅同步使用 `flag=aerion`。Clash/Mihomo YAML 仍可作为文件格式导入；文件格式兼容不代表 Mihomo 内核支持 Flux。PxBoard 对应的独立入口为 `format=aerion`，显式的 `format=clash` 始终保留普通 Mihomo 行为。

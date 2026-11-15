# Aerion / Neto 订阅适配器

Aerion、Neto 与 XBClient 使用独立的 `App\Protocols\Aerion` 适配器。订阅地址保留原有路径和令牌，使用 `flag=aerion`、`flag=neto` 或 `flag=xbclient` 选择；未指定 `flag` 时，也可通过 `User-Agent: Aerion`、`Neto` 或 `XBClient` 自动识别。

适配器输出 YAML，沿用现有 `clashmeta` 模板中的代理组、规则及标准协议字段。Aerion 和 ClashMeta 分别继承基础协议类，独立维护支持的协议列表与能力过滤；Aerion 不继承 Mihomo 适配器或其客户端版本要求。两者共用 `YamlSubscription` 渲染代码，标准字段继续调用已有序列化方法，避免维护两份相同代码。

Neto 与 XBClient 桌面端、安卓端订阅同步使用 `flag=aerion`。PxBoard 对应的独立入口为 `format=aerion`，显式的 `format=clash` 始终保留普通 Mihomo 行为。

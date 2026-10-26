# 服务标识与归属图标

沿用现有原生检查器、系统字体和语义配色。应用自己的盾牌图标保持；品牌图标只标识对应服务，不作为应用品牌，不重绘或按告警状态染色。

- 品牌源：Net.Coffee 同款自托管 Claude / ChatGPT / Cloudflare 资源；原始文件、网址、SHA-256 见 SOURCES.json。商标分别属于 Anthropic、OpenAI 和 Cloudflare。设计参考 https://claude.com/ 、https://openai.com/brand/ 、https://www.cloudflare.com/press/press-kit/ 。
- Claude 保留陶土色星形，ChatGPT 保留黑白标识，Cloudflare 保留橙色云。白色中性承托兼容两种主题；颜色来自原图，不手工改色。
- 页面头部标识 26pt，承托框位 40pt；侧栏 14pt、18pt 框位；服务行 18–20pt；图文间距 8pt（连接图保持既有 9–10pt 网格）。
- IP 国旗：flag-icons 7.3.2，4:3，MIT。原始 SVG 保留；渲染为 72×54，本机显示 18×13.5pt，连接图 16×12pt，圆角 2pt、细描边 0.5pt。
- 归属代码只取已有 API countryCode / country_code，或已有明确国家名；缺少可靠归属时不显示旗帜，不按 IP 或节点名称猜测。
- 归属文案顺序为国家、地区、城市、运营商，去除重复地名；不改变原始 JSON、采集器和检测结论。
- 字体继续使用既有 SF 系统字级与等宽 IP 字体；状态色继续沿用现有 Palette 的 mint / blue / amber，品牌颜色不表示安全等级。
- 所有图片本地打包；不会为显示 Logo 或国旗增加网络请求。

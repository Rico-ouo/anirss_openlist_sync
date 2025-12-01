# anirss-openlist-sync

由于anirss不支持云端的遗漏检测，所以嘞拿ai搓了一个，支持openlist的遗漏检测

## 功能特性

- ✅ 检测 anirss 本地已下载但 openlist 云端缺失的文件
- ✅ 删除本地遗漏文件（支持 qbit 种子和本地文件同步删除）
- ✅ 智能跳过正在下载的种子
- ✅ 跳过剧场版（可选）
- ✅ 支持 qbit 集成，检查下载状态
- ✅ 自动删除长时间无速度的种子
- ✅ 可配置的种子最大保留时间
- ✅ 检查 openlist 上传任务，避免删除正在上传的种子
- ✅ 多线程检测，可配置的线程池大小

## 使用说明

环境要求Python 3.11+

必要文件就一个anirss_openlist_sync.py

进入项目目录，执行以下命令安装依赖：

```bash
pip install requests
```

运行:

```bash
python anirss_openlist_sync.py
```

首次运行脚本会自动生成 `config.ini` 配置文件，根据需要修改配置项。

## 删除逻辑

脚本会根据以下条件判断是否应该删除种子：

1. **种子不在 qbit 中并不存在于 openlist 上传任务**：直接删除
2. **种子状态**：只处理正在下载状态且速度为 0 才会删除
3. **种子年龄**：超过配置的 `max_age_hours` 才会删除
4. **openlist 上传任务**：如果存在相关的 openlist 上传任务，则跳过删除

## 注意事项

1. 请确保 anirss、openlist 和 qbit 服务已正常启动
2. 请确保配置文件中的 API 地址、用户名和密码正确
3. 删除操作不可逆，请谨慎使用删除功能
4. 建议先使用遗漏检测查看遗漏文件，确认无误后再执行删除操作
5. 首次运行会生成配置文件，建议先检查配置文件是否正确

## 贡献指南

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License

## 致谢

感谢以下开源项目的支持：

- **OpenList**：一个基于AGPL-3.0许可证的开源文件列表项目，提供了强大的文件管理功能。
  - 项目链接：[https://github.com/OpenListTeam/OpenList](https://github.com/OpenListTeam/OpenList)
  - 许可证：AGPL-3.0

- **ani-rss**：一个基于RSS自动追番、订阅、下载、刮削的开源项目。
  - 项目链接：[https://github.com/wushuo894/ani-rss](https://github.com/wushuo894/ani-rss)
  - 许可证：GPL-2.0
# SQLite → D1 导入

两个脚本可用于五个站点的 SQLite 数据库。先停止写入，导出器会通过 SQLite backup API 取得包含 WAL 内容的一致快照，并在内存数据库回放 SQL，校验数据和外键。

```sh
python scripts/export_sqlite_to_d1.py /path/to/site.sqlite3 /path/to/site-export
python scripts/apply_d1_import.py /path/to/site-export/manifest.json SITE_DB \
  --config /path/to/deployment/wrangler.toml --remote
```

导入器按清单顺序执行 SQL，先检查目标 D1 没有用户表，最后核对各表行数和外键。目标必须是**新建的空 D1**。若中途失败，废弃该目标并在新建的空 D1 重跑；脚本不会删除或覆盖已有数据。可用 `--local` 对 Wrangler 本地 D1 演练。

每个 SQL 文件和快照有 SHA-256 清单。切换前还需按业务关键记录抽样核对、确认 D1 schema 与当前应用版本一致，并完成登录及核心流程测试。

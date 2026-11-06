# TITD

> **TI** = 测试集成 · **TD** = 测试交付

这里是用来折腾 GitHub Actions 的整活仓库喵～

CI/CD 试验田、workflow 沙盒、随便跑跑就删的分支，都往这儿扔。

- 业务代码？没有的。
- 稳定性？看心情的。
- 有用吗？用来测 workflow 就够了喵。

```yaml
name: 整活
on: [push, workflow_dispatch]
jobs:
  meow:
    runs-on: ubuntu-latest
    steps:
      - run: echo "喵"
```

## 演练：磁力种子 + web seed

`drill/torrent-webseed` 分支上的 `torrent-drill.yml` 验证一条链路：
把 WeQ Release 的全部产物打成带 web seed 的磁力种子，发到 QQ 群，
用户下种后不必依赖任何常驻做种者。

```bash
node scripts/make-torrent.mjs --dir <产物目录> --out-dir <种子目录> \
  --url-base https://github.com/<repo>/releases/download/<tag> --piece-size 4MiB

node scripts/verify-torrent.mjs --torrent-dir <种子目录> --dist <产物目录> \
  --url-base https://github.com/<repo>/releases/download/<tag>
```

实测结论（aria2 1.37 / libtorrent 2.1）：

- GitHub Release 直链 302 到签名 CDN 后完整支持 `Range`，可作为 BEP 19 web seed。
- 多文件种子没法直接映射到平铺的 Release 资产 —— 客户端会在 URL 后面拼
  `<种子名>/<相对路径>`。所以改成**每个产物一个单文件种子**。
- 单文件种子的 `url-list` 必须用**数组**形式，里面放该文件的精确 URL。
  数组形式下客户端原样使用；字符串前缀形式反而会拼错。
- 实测下载 9–15 MiB/s，sha256 与 Release 原件一致。

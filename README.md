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

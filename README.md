# 学校官网 MVP

一个最小可用的“学校官网”示例，包含：公告栏、家长登录、学生档案页、管理后台（公告/文章/档案）。

## 本地运行

1. 安装依赖（已写入 `package.json`）
```bash
npm i
```
2. 开发启动（热重载）
```bash
npm run dev
```
3. 生产启动
```bash
npm start
```
4. 打开浏览器访问 `http://localhost:3000`

## 账号信息（MVP 假数据）

- 家长账号
  - 学号：`20230001` 密码：`123456`
  - 学号：`20230002` 密码：`abcdef`
- 管理员
  - 用户名：`admin` 密码：`admin123`

## 主要功能

- 官网首页 `/`
  - 公告栏（含固定“禁止发型类型”示例）
  - 新闻/文章区域
  - 家长登录入口（学号 + 密码）
- 学生档案页 `/records`（登录后）
  - 成绩单、处分单；无记录时显示“暂无记录”
- 管理后台 `/admin`
  - 登录 `/admin/login`
  - 公告新增/删除
  - 文章新增/删除
  - 为指定学号新增档案（成绩单/处分单）

## 数据存储

- 使用本地 JSON 文件（位于 `data/` 目录）
  - `announcements.json` 公告列表
  - `articles.json` 文章列表
  - `users.json` 家长账号（学号/密码）
  - `records.json` 学生档案（按学号存储）
- 首次运行会自动写入示例数据。

## 技术栈

- Node.js + Express
- 视图：EJS 模板
- 会话：express-session
- 样式：基础 CSS（`public/styles.css`）

## 后续扩展建议（非 MVP）

- 荣誉证书模块、文件上传（PDF/图片）
- 学号批量导入与管理、公告分类
- 切换为数据库（如 SQLite/Postgres），并加入权限/审计

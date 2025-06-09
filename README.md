# Angular Auth Analyzer

Angular認証実装を解析するためのCLIツールです。Angularアプリケーションの認証関連コードを静的解析し、セキュリティ問題を検出します。

## 特徴

- 🔍 **認証ガード分析** - CanActivate、CanLoadなどのルートガードを検出
- 🔐 **認証サービス分析** - 認証関連サービスとメソッドを特定
- 🛡️ **セキュリティ分析** - 潜在的なセキュリティ問題を検出
- 📊 **多様な出力形式** - テーブル、JSON、YAML形式での出力
- ⚡ **高速解析** - Rustによる高速な静的解析

## インストール

### 前提条件

- Rust 1.70以上
- Cargo

### ビルド

```bash
git clone <repository-url>
cd angular-auth-analyzer
cargo build --release
```

### 実行ファイルの配置（オプション）

```bash
# 実行ファイルをPATHに追加
cargo install --path .
```

## 使用方法

### 基本的な使用方法

```bash
# 基本的な全体分析
cargo run -- -p /path/to/your/angular/project

# または、インストール済みの場合
angular-auth-analyzer -p /path/to/your/angular/project
```

### コマンドラインオプション

```bash
angular-auth-analyzer [OPTIONS] [SUBCOMMAND]

OPTIONS:
    -p, --path <PATH>       Angular プロジェクトのルートパス [必須]
    -o, --output <OUTPUT>   出力形式 (table, json, yaml) [デフォルト: table]
    -d, --detailed          詳細な解析結果を表示
    -h, --help              ヘルプを表示
    -V, --version           バージョンを表示
```

### サブコマンド

#### 1. ガード分析のみ

```bash
# 認証ガードのみを解析
angular-auth-analyzer -p ./my-app guards

# 詳細出力
angular-auth-analyzer -p ./my-app guards -d
```

**検出される要素:**
- CanActivate ガード
- CanLoad ガード
- CanActivateChild ガード
- ガードの依存関係
- 認証チェックメソッド

#### 2. サービス分析のみ

```bash
# 認証サービスのみを解析
angular-auth-analyzer -p ./my-app services

# JSON形式で出力
angular-auth-analyzer -p ./my-app services -o json
```

**検出される要素:**
- 認証サービス
- ログイン/ログアウトメソッド
- トークンストレージ方法
- APIエンドポイント

#### 3. ルート分析のみ

```bash
# 保護されたルートのみを解析
angular-auth-analyzer -p ./my-app routes
```

**検出される要素:**
- 保護されたルート
- ルートガードの設定
- 遅延読み込み設定

#### 4. セキュリティ分析

```bash
# セキュリティ問題の検出
angular-auth-analyzer -p ./my-app security
```

**検出される問題:**
- 不安全なトークンストレージ（localStorage使用）
- CSRF保護の欠如
- ハードコードされたシークレット
- 保護されていないルート

### 出力形式

#### テーブル形式（デフォルト）

```bash
angular-auth-analyzer -p ./my-app
```

```
╭─ Complete Authentication Analysis ─╮
│ Guards found: 3                     │
│ Services found: 2                   │
│ Components with auth: 5             │
│ Interceptors found: 1               │
│ Protected routes: 8                 │
│ Security issues: 1                  │
╰─────────────────────────────────────╯
```

#### JSON形式

```bash
angular-auth-analyzer -p ./my-app -o json
```

```json
{
  "guards": [
    {
      "name": "AuthGuard",
      "file_path": "./src/app/guards/auth.guard.ts",
      "guard_type": "CanActivate",
      "dependencies": ["AuthService"],
      "auth_check_methods": ["canActivate"]
    }
  ],
  "services": [...],
  "potential_issues": [
    "Potential insecure token storage detected (localStorage)"
  ]
}
```

#### YAML形式

```bash
angular-auth-analyzer -p ./my-app -o yaml
```

```yaml
guards:
  - name: AuthGuard
    file_path: "./src/app/guards/auth.guard.ts"
    guard_type: CanActivate
    dependencies:
      - AuthService
    auth_check_methods:
      - canActivate
services: []
potential_issues:
  - "Potential insecure token storage detected (localStorage)"
```

## 使用例

### 1. 新しいプロジェクトの認証実装チェック

```bash
# 全体的な認証実装を確認
angular-auth-analyzer -p ./new-project -d

# セキュリティ問題のみをチェック
angular-auth-analyzer -p ./new-project security
```

### 2. 既存プロジェクトのセキュリティ監査

```bash
# JSON形式で詳細な解析結果を取得
angular-auth-analyzer -p ./production-app -o json -d > auth-audit.json

# セキュリティ問題を特定
angular-auth-analyzer -p ./production-app security
```

### 3. CI/CDパイプラインでの自動チェック

```bash
#!/bin/bash
# セキュリティ問題がある場合は失敗させる
angular-auth-analyzer -p ./src security -o json > security-report.json

# セキュリティ問題の数をチェック
issues=$(jq length security-report.json)
if [ "$issues" -gt 0 ]; then
  echo "Security issues found: $issues"
  exit 1
fi
```

## 検出パターン

### 認証ガード

- `CanActivate` インターフェースの実装
- `CanLoad` インターフェースの実装
- `CanActivateChild` インターフェースの実装

### 認証サービス

- `@Injectable` デコレータ付きのサービス
- `login`, `authenticate`, `token` を含むメソッド
- `AuthService` という名前のサービス

### セキュリティ問題

- `localStorage.setItem` でのトークン保存
- CSRF保護の欠如（`HttpClientXsrfModule` の未使用）
- 正規表現パターンによるハードコードされたシークレット検出

## 制限事項

- 静的解析のため、動的に生成されるコードは検出できません
- TypeScript/Angularのバージョンによっては一部のパターンが検出されない場合があります
- 現在はルート解析機能は基本実装のみです

## 今後の改善予定

- [ ] TypeScript AST解析の導入
- [ ] より詳細なルート解析
- [ ] Angular v17+ の新機能対応
- [ ] カスタムパターンの設定機能
- [ ] HTMLテンプレート内の認証ディレクティブ解析

## 貢献

バグ報告や機能要望は Issue にてお願いします。プルリクエストも歓迎します。

## ライセンス

MIT License

## 作者

あなたの名前 <your.email@example.com>

---

**注意**: このツールは静的解析ツールです。実際のセキュリティ監査では、動的テストや専門家によるレビューも併用することを推奨します。


良い質問ですね！現在表示されている分析結果の各項目について詳しく説明します。

## 分析項目の詳細

### 1. **Guards found: 5**
これはAngularの**ルートガード**を検出した数です。
- **CanActivate**: ページにアクセスする前に認証チェックを行う
- **CanLoad**: モジュールを遅延読み込みする前にチェックを行う
- **CanActivateChild**: 子ルートへのアクセスをチェック

例：ログインしていないユーザーが管理画面にアクセスしようとした時に、自動的にログインページにリダイレクトする仕組み

### 2. **Services found: 10**
**認証関連のサービス**を検出した数です。
- ログイン/ログアウト処理を行うサービス
- JWTトークンを管理するサービス
- ユーザー情報を管理するサービス

例：`AuthService`, `TokenService`, `UserService`など

### 3. **Components with auth: 5**
**認証ロジックを含むコンポーネント**の数です。
- ログインフォームコンポーネント
- ユーザープロフィール表示コンポーネント
- 認証状態によって表示内容が変わるコンポーネント

### 4. **Interceptors found: 5**
**HTTPインターセプター**の数です。
- APIリクエストに自動的にJWTトークンを追加
- 認証エラー（401/403）を自動的にハンドリング
- リクエスト/レスポンスの前処理・後処理

### 5. **Protected routes: 0**
**保護されたルート**の検出数です。
- 現在は基本実装のため、0になっています
- 実際にはガードが設定されたルートが存在するはずです

### 6. **Security issues: 2**
**セキュリティ上の問題**が2件検出されています。

詳細を確認するには：
```bash
cargo run -- -p ..\NEWTON-Frontend\ security
```

## より詳細な情報を見る方法

### 1. 詳細分析
```bash
cargo run -- -p ..\NEWTON-Frontend\ -d
```

### 2. 各カテゴリ別の詳細確認
```bash
# ガードの詳細
cargo run -- -p ..\NEWTON-Frontend\ guards -d

# サービスの詳細  
cargo run -- -p ..\NEWTON-Frontend\ services -d

# セキュリティ問題の詳細
cargo run -- -p ..\NEWTON-Frontend\ security
```

### 3. JSON形式で全データを確認
```bash
cargo run -- -p ..\NEWTON-Frontend\ -o json -d
```

**セキュリティ問題が2件**検出されているのが気になりますね。まずはこれを確認してみることをお勧めします：

```bash
cargo run -- -p ..\NEWTON-Frontend\ security
```

どの項目について詳しく知りたいですか？
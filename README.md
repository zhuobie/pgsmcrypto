## 简介

国密算法的PostgreSQL插件，基于Rust和pgrx库构建。包含功能：

- SM3消息摘要算法

- SM2签名/验签、加密/解密、ASN.1编码支持

- SM2密钥对生成、公钥/私钥合法验证、公钥/私钥导入导出等

- SM4加密/解密，包含ECB模式和CBC模式

## 快速开始

### SM3消息摘要算法

直接对文本进行hash，返回64位16进制字符串（32字节）：

```sql
select sm3_hash_string('abc');
```

对bytea类型进行hash：

```sql
select sm3_hash(E'\\x616263');
```

也可以这样：

```sql
select sm3_hash('abc'::bytea);
```

### SM2非对称加密算法

#### 秘钥相关

生成随机的密钥对，返回一个数组，第1个元素是私钥，第2个元素是对应的公钥，私钥和公钥分别以64位或128位16进制字符串表示。

```sql
select sm2_gen_keypair();
```

这将返回一个数组，表示密钥对，后面的示例都基于这个随机生成的密钥对。

```
{f7748bf23df84c431574f169524da5e0bee10c6aa0731dd923583fb39058e185,80936e55add759c1c00b4fc688904faf6416a4f9ee71f18f4e5edca1a839b7bc8b13a3f28e2ba5c342cae82d73659d73a68aa479aba0ae2d812215c97b7c5ad7}
```

如果使用自定义的私钥或公钥，可以使用内置函数判断私钥和公钥的合法性，返回值为`1`则合法，返回值为`0`则非法。

```sql
select sm2_privkey_valid('f7748bf23df84c431574f169524da5e0bee10c6aa0731dd923583fb39058e185');
select sm2_pubkey_valid('80936e55add759c1c00b4fc688904faf6416a4f9ee71f18f4e5edca1a839b7bc8b13a3f28e2ba5c342cae82d73659d73a68aa479aba0ae2d812215c97b7c5ad7');
```

可以将私钥或公钥转换为pem格式的字节串，方便与其他系统进行交换。

```sql
select sm2_keypair_to_pem_bytes('f7748bf23df84c431574f169524da5e0bee10c6aa0731dd923583fb39058e185');
select sm2_pubkey_to_pem_bytes('80936e55add759c1c00b4fc688904faf6416a4f9ee71f18f4e5edca1a839b7bc8b13a3f28e2ba5c342cae82d73659d73a68aa479aba0ae2d812215c97b7c5ad7');
```

pem格式的字节串可以转换为文本格式，可以在PostgreSQL或任何一种编程语言中进行转换，或将其保存到本地。

```sql
with CTE as (
    select sm2_keypair_to_pem_bytes('f7748bf23df84c431574f169524da5e0bee10c6aa0731dd923583fb39058e185') as keypair_bytes
)
select encode(keypair_bytes, 'escape') from CTE;
```

这将返回以下内容：

```
 -----BEGIN PRIVATE KEY-----                                     +
 MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg93SL8j34TEMVdPFp+
 Uk2l4L7hDGqgcx3ZI1g/s5BY4YWhRANCAASAk25VrddZwcALT8aIkE+vZBak+e5x+
 8Y9OXtyhqDm3vIsTo/KOK6XDQsroLXNlnXOmiqR5q6CuLYEiFcl7fFrX        +
 -----END PRIVATE KEY-----                                       +
```

同样也可以导出公钥到pem字节串：

```sql
with CTE as (
    select sm2_pubkey_to_pem_bytes('80936e55add759c1c00b4fc688904faf6416a4f9ee71f18f4e5edca1a839b7bc8b13a3f28e2ba5c342cae82d73659d73a68aa479aba0ae2d812215c97b7c5ad7') as pubkey_bytes
)
select encode(pubkey_bytes, 'escape') from CTE;
```

这将返回以下内容：

```
 -----BEGIN PUBLIC KEY-----                                      +
 MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEgJNuVa3XWcHAC0/GiJBPr2QWpPnu+
 cfGPTl7coag5t7yLE6Pyjiulw0LK6C1zZZ1zpoqkeaugri2BIhXJe3xa1w==    +
 -----END PUBLIC KEY-----                                        +
 ```

也可以从pem字节串中读取密钥对：

```sql
with CTE as (
    select sm2_keypair_to_pem_bytes('f7748bf23df84c431574f169524da5e0bee10c6aa0731dd923583fb39058e185') as keypair_bytes
)
select sm2_keypair_from_pem_bytes(keypair_bytes) from CTE;
```

同理可以从pem字节串中读取公钥：

```sql
with CTE as (
    select sm2_pubkey_to_pem_bytes('80936e55add759c1c00b4fc688904faf6416a4f9ee71f18f4e5edca1a839b7bc8b13a3f28e2ba5c342cae82d73659d73a68aa479aba0ae2d812215c97b7c5ad7') as pubkey_bytes
)
select sm2_pubkey_from_pem_bytes(pubkey_bytes) from CTE;
```

如果知道私钥，可以使用内置函数计算出对应的公钥：

```sql
select sm2_pk_from_sk('f7748bf23df84c431574f169524da5e0bee10c6aa0731dd923583fb39058e185');
```

#### 签名和验签

这个函数用来对消息本身进行签名和验签，如果消息或数据过大，则计算可能会非常缓慢。

如果验签返回值为`1`则表明验证通过，如果返回值为`0`则代表验证不通过：

```sql
with CTE as (
    select sm2_sign_raw('abc'::bytea, 'f7748bf23df84c431574f169524da5e0bee10c6aa0731dd923583fb39058e185') as sign_bytes
)
select sm2_verify_raw('abc'::bytea, sign_bytes, '80936e55add759c1c00b4fc688904faf6416a4f9ee71f18f4e5edca1a839b7bc8b13a3f28e2ba5c342cae82d73659d73a68aa479aba0ae2d812215c97b7c5ad7') from CTE;
```

这个函数是按照SM2使用规范，对消息、id等组合的数据的SM3消息摘要进行签名和验签，是推荐的使用方式：

```sql
with CTE as (
    select sm2_sign('zhuobie'::bytea, 'abc'::bytea, 'f7748bf23df84c431574f169524da5e0bee10c6aa0731dd923583fb39058e185') as sign_bytes
)
select sm2_verify('zhuobie'::bytea, 'abc'::bytea, sign_bytes, '80936e55add759c1c00b4fc688904faf6416a4f9ee71f18f4e5edca1a839b7bc8b13a3f28e2ba5c342cae82d73659d73a68aa479aba0ae2d812215c97b7c5ad7') from CTE;
```

#### 加密和解密

SM2算法可以进行非对称加密和解密，这是原始的函数，输入和输出均为bytea字节串。SM2加密和解密只适合短小的文本消息，如果数据量过大，则加密和解密过程会非常缓慢。

```sql
with CTE as (
    select sm2_encrypt('abc'::bytea, '80936e55add759c1c00b4fc688904faf6416a4f9ee71f18f4e5edca1a839b7bc8b13a3f28e2ba5c342cae82d73659d73a68aa479aba0ae2d812215c97b7c5ad7') as enc
)
select sm2_decrypt(enc, 'f7748bf23df84c431574f169524da5e0bee10c6aa0731dd923583fb39058e185')
from CTE;
```

使用密文`c1c2c3`排列方式进行加密和解密：

```sql
with CTE as (
    select sm2_encrypt_c1c2c3('abc'::bytea, '80936e55add759c1c00b4fc688904faf6416a4f9ee71f18f4e5edca1a839b7bc8b13a3f28e2ba5c342cae82d73659d73a68aa479aba0ae2d812215c97b7c5ad7') as enc
)
select sm2_decrypt_c1c2c3(enc, 'f7748bf23df84c431574f169524da5e0bee10c6aa0731dd923583fb39058e185')
from CTE;
```

对密文使用ASN.1编码，这是SM2使用规范中推荐的方式：

```sql
with CTE as (
    select sm2_encrypt_asna1('abc'::bytea, '80936e55add759c1c00b4fc688904faf6416a4f9ee71f18f4e5edca1a839b7bc8b13a3f28e2ba5c342cae82d73659d73a68aa479aba0ae2d812215c97b7c5ad7') as enc
)
select sm2_decrypt_asna1(enc, 'f7748bf23df84c431574f169524da5e0bee10c6aa0731dd923583fb39058e185')
from CTE;
```

为了方便使用，可以直接将数据加密为16进制字符串，当然也可以使用PostgreSQL自带的函数来完成。

```sql
with CTE as (
    select sm2_encrypt_hex('abc'::bytea, '80936e55add759c1c00b4fc688904faf6416a4f9ee71f18f4e5edca1a839b7bc8b13a3f28e2ba5c342cae82d73659d73a68aa479aba0ae2d812215c97b7c5ad7') as enc
)
select sm2_decrypt_hex(enc, 'f7748bf23df84c431574f169524da5e0bee10c6aa0731dd923583fb39058e185')
from CTE;
```

为了方便使用，同时提供直接将数据加密为base64字符串的函数：

```sql
with CTE as (
    select sm2_encrypt_base64('abc'::bytea, '80936e55add759c1c00b4fc688904faf6416a4f9ee71f18f4e5edca1a839b7bc8b13a3f28e2ba5c342cae82d73659d73a68aa479aba0ae2d812215c97b7c5ad7') as enc
)
select sm2_decrypt_base64(enc, 'f7748bf23df84c431574f169524da5e0bee10c6aa0731dd923583fb39058e185')
from CTE;
```

### SM4对称加密算法

#### ECB模式

ECB模式加密和解密简单、快速，但相同的明文加密后的密文是一致的。如果原始数据中包含大量重复数据，这可能导致别人从密文中能够推测出原始数据的结构。

这是原始的函数，加密和解密都使用同样的16字节秘钥。

```sql
with CTE as (
    select sm4_encrypt_ecb('abc'::bytea, '1234567812345678'::bytea) as enc
)
select sm4_decrypt_ecb(enc, '1234567812345678'::bytea) from CTE;
```

为了方便使用，提供将明文直接加密为base64格式密文的函数：

```sql
with CTE as (
    select sm4_encrypt_ecb_base64('abc'::bytea, '1234567812345678'::bytea) as enc
)
select sm4_decrypt_ecb_base64(enc, '1234567812345678'::bytea) from CTE;
```

为了方便使用，提供将明文直接加密为16进制字符串的函数：

```sql
with CTE as (
    select sm4_encrypt_ecb_hex('abc'::bytea, '1234567812345678'::bytea) as enc
)
select sm4_decrypt_ecb_hex(enc, '1234567812345678'::bytea) from CTE;
```

#### CBC模式

在CBC模式下，需要提供一个初始向量，跟秘钥一样也是16字节，相比ECB模式安全性更高。

```sql
with CTE as (
    select sm4_encrypt_cbc('abc'::bytea, '1234567812345678'::bytea, '0000000000000000'::bytea) as enc
)
select sm4_decrypt_cbc(enc, '1234567812345678'::bytea, '0000000000000000'::bytea) from CTE;
```

为了方便使用，提供直接将明文加密为base64格式密文的函数：

```sql
with CTE as (
    select sm4_encrypt_cbc_base64('abc'::bytea, '1234567812345678'::bytea, '0000000000000000'::bytea) as enc
)
select sm4_decrypt_cbc_base64(enc, '1234567812345678'::bytea, '0000000000000000'::bytea) from CTE;
```

为了方便使用，提供直接将明文加密为16进制字符串密文的函数：

```sql
with CTE as (
    select sm4_encrypt_cbc_hex('abc'::bytea, '1234567812345678'::bytea, '0000000000000000'::bytea) as enc
)
select sm4_decrypt_cbc_hex(enc, '1234567812345678'::bytea, '0000000000000000'::bytea) from CTE;
```

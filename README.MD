## SpringBoot KISA SEED 암복호화
- BouncyCastle JCE Provider 
- Java 11
- SpringBoot 

### 암호화 알고리즘, 모드, 패딩
- SEED/CBC/PKCS5Padding


BouncyCastle을 Static하게 설정하고 싶으면 jce 설정 파일(java.security)에 아래와 같이 추가한다.  
jce 설정 파일위치는 해당 Java 배포판 문서를 확인하고 아래  "##" 부분은 기존 Provider 다음 번호를 적용하면 된다.

```shell
security.provider.##=org.bouncycastle.jce.provider.BouncyCastleProvider
```




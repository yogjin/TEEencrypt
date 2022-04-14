## Goals
OP-TEE를 통해 TEE(Trusted Execution Environment)에 대해 이해하고 

OP-TEE 내에서 동작하는 어플리케이션(TA, Trusted Application + CA, Client Application)을 작성해본다. 

해당 프로그램은 OP-TEE 내에서 동작하는 애플리케이션(TA, Trusted Application + CA, Client Application)이다.

## What is OP-TEE?

OP-TEE는 ARM 기반의 리눅스 오픈 소스를 지향하는 비영리 단체 Linaro에서 배포하는 TrustZone기술이 적용된 TEE(Trusted Execution Environment)를 구현한 오픈소스이다.

ARM TrustZone은 하나의 장치에 하드웨어적으로 분리된 두 개의 환경(REE, TEE)을 제공한다.

일반적인 실행환경을 REE(Normal world)라고 하며, 보안기능을 보호하고 신뢰된 코드만을 실행하는 환경을 TEE(Secure world)라고 한다.

ARM TrustZone의 애플리케이션은 CA(Normal world App)와 TA(Secure worldApp)로 구분되며 둘은 짝을 이루며 동작한다.

각 TA는 UUID를 가지고 있기 때문에, 이 ID에 대한 정보를 가지고 있는 CA 혹은
TA만 client/internal API를 통해 특정 TA 서비스를 요청할 수 있다.

## How to use
![image](https://user-images.githubusercontent.com/33623078/163444455-c22a03cf-818b-40f2-8f08-3254eba77b22.png)
![image](https://user-images.githubusercontent.com/33623078/163444920-86215ac8-67ac-4311-b1b5-e7075bcc974f.png)
![image](https://user-images.githubusercontent.com/33623078/163445175-3a5736fa-6fa5-4e2d-8820-c3b4ea9cf7e3.png)

## Command

![image](https://user-images.githubusercontent.com/33623078/163445820-c4e19e5f-b45f-4d9e-b06a-294737da1926.png)
![image](https://user-images.githubusercontent.com/33623078/163446340-b0530347-f425-4bc0-b88c-c4c1bcb12528.png)
![image](https://user-images.githubusercontent.com/33623078/163446665-7cfb806d-0e5f-4f51-8ae6-a5cf895cf0c5.png)

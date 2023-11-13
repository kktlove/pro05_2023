# 1.반영사항
- 스프링부트3 프로젝트
  - 스프링부트 : 3.1.1
  - 자바 : 17
  - 빌드 : maven
  - pom.xml 버전 정보가 많이 바뀌었습니다. 최신 pom.xml 버전을 참고하시기 바랍니다.
  - javax에서 jakarta로 변경됨에 따라서 많은 import 들이 jakarta로 수정되었습니다.
    - javax.validation => jakarta.validation
    - javax.persistence => jakarta.persistence
    - CustomAuthenticationEntryPoint.java (javax.servlet => jakarta.servlet)
    - Security 버전이 수정됨에 따라 기존 메소드가 deprecated 되었습니다.


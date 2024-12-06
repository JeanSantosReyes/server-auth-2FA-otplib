# SERVER AUTH 2FA WITH OTPLIB

## Registrar un Usuario:
Método: POST

URL: http://localhost:3000/register
```
{
  "username": "testuser",
  "password": "testpassword"
}
```


## Generar el Código QR para 2FA:
Método: POST

URL: http://localhost:3000/setup-2fa
```
{
  "username": "testuser"
}
```


## Verificar el Código 2FA:
Método: POST

URL: http://localhost:3000/verify-2fa
```
{
  "username": "testuser",
  "token": "123456"
}
```
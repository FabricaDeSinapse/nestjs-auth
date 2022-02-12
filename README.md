# Autenticação (Sistema de Login) com Token JWT

{% embed url="https://www.youtube.com/watch?v=3z6Cs_PtYc0" %}

**Link do repositório no GitHub:** [https://github.com/FabricaDeSinapse/nestjs-auth](https://github.com/FabricaDeSinapse/nestjs-auth)

**Link do Miro:** [https://miro.com/app/board/uXjVOXehwN4=/](https://miro.com/app/board/uXjVOXehwN4=/)

## Iniciando um projeto NestJS

Antes de iniciar, certifique-se de que você possui um projeto NestJS criado e que a CLI do NestJS está instalada no seu computador.

## Prisma

### Instalar o prisma

```bash
npm install -D prisma
```

### Inicializar o prisma

```bash
npx prisma init
```

### `prisma/schema.prisma`

```java
// This is your Prisma schema file,
// learn more about it in the docs: https://pris.ly/d/prisma-schema

datasource db {
  provider = "sqlite"
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

model User {
  id Int @id @default(autoincrement())

  email    String @unique
  password String

  name String
}
```

## Arquivo `.env`

```bash
# Configuration

JWT_SECRET=""

# Database

DATABASE_URL=""
```

### Arquivo `.env` preenchido

```bash
# Configuration

JWT_SECRET="texto aleatório para proteger sua aplicação"

# Database

DATABASE_URL="file:./sqlite.db"
```

## Migrar o banco

```bash
npx prisma migrate dev --name init
```

Esse comando deverá instalar a dependência `@prisma/client` no projeto.

### Criação do módulo do prisma

#### Comandos na CLI para criação dos arquivos

```bash
nest g module prisma
nest g service prisma
```

#### Conteúdo dos arquivos

##### `src/prima/prisma.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
```

##### `src/prisma/prisma.service.ts`

```typescript
import { INestApplication, Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  async onModuleInit() {
    await this.$connect();
  }

  async enableShutdownHooks(app: INestApplication) {
    this.$on('beforeExit', async () => {
      await app.close();
    });
  }
}
```

## Dependências

- `@nestjs/passport`
- `@nestjs/jwt`
- `bcrypt`
- `class-validator`
- `class-transformer`
- `passport`
- `passport-jwt`
- `passport-local`

Comando para instalar tudo ao mesmo tempo:

```bash
npm i @nestjs/passport @nestjs/jwt bcrypt class-validator class-transformer passport passport-jwt passport-local
```

## Dependências Dev

- `@types/passport-jwt`
- `@types/passport-local`
- `@types/bcrypt`

```bash
npm i -D @types/passport-jwt @types/passport-local @types/bcrypt
```

## Códigos

### Usuários que serão autenticados: diretório `src/user`

#### Comando do terminal para criação dos arquivos

```bash
nest g resource user
```

#### `src/user/entities/user.entity.ts`

```typescript
export class User {
  id?: number;
  email: string;
  password: string;
  name: string;
}
```

#### `src/user/dto/create-user.dto.ts`

```typescript
import { User } from '../entities/user.entity';
import {
  IsEmail,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

export class CreateUserDto extends User {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(4)
  @MaxLength(20)
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'password too weak',
  })
  password: string;

  @IsString()
  name: string;
}
```

#### `src/user/user.controller.ts`

```typescript
import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }
}
```

#### `src/user/user.service.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './entities/user.entity';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const data: Prisma.UserCreateInput = {
      ...createUserDto,
      password: await bcrypt.hash(createUserDto.password, 10),
    };

    const createdUser = await this.prisma.user.create({ data });

    return {
      ...createdUser,
      password: undefined,
    };
  }

  findByEmail(email: string) {
    return this.prisma.user.findUnique({ where: { email } });
  }
}
```

### `src/user/user.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';

@Module({
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}
```

### Ativando validação do `class-validator` no arquivo `main.ts`

```typescript
import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Pipes
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  await app.listen(3000);
}

bootstrap();
```

### Autenticação: diretório `auth`

```bash
nest g module auth
nest g controller auth
nest g service auth
```

#### `src/auth/auth.module.ts`

```typescript
import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { UserModule } from '../user/user.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { LoginValidationMiddleware } from './middlewares/login-validation.middleware';

@Module({
  imports: [
    UserModule,
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '30d' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, LocalStrategy, JwtStrategy],
})
export class AuthModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoginValidationMiddleware).forRoutes('login');
  }
}
```

#### `src/auth/auth.controller.ts`

```typescript
import {
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { AuthRequest } from './models/AuthRequest';
import { IsPublic } from './decorators/is-public.decorator';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @IsPublic()
  @UseGuards(LocalAuthGuard)
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Request() req: AuthRequest) {
    return this.authService.login(req.user);
  }
}
```

#### `src/auth/auth.service.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UnauthorizedError } from './errors/unauthorized.error';
import { User } from '../user/entities/user.entity';
import { UserService } from '../user/user.service';
import { UserPayload } from './models/UserPayload';
import { UserToken } from './models/UserToken';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
  ) {}

  async login(user: User): Promise<UserToken> {
    const payload: UserPayload = {
      sub: user.id,
      email: user.email,
      name: user.name,
    };

    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async validateUser(email: string, password: string): Promise<User> {
    const user = await this.userService.findByEmail(email);

    if (user) {
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (isPasswordValid) {
        return {
          ...user,
          password: undefined,
        };
      }
    }

    throw new UnauthorizedError(
      'Email address or password provided is incorrect.',
    );
  }
}
```

#### `src/auth/strategies/jwt.strategy.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UserFromJwt } from '../models/UserFromJwt';
import { UserPayload } from '../models/UserPayload';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  async validate(payload: UserPayload): Promise<UserFromJwt> {
    return {
      id: payload.sub,
      email: payload.email,
      name: payload.name,
    };
  }
}
```

#### `src/auth/guards/jwt-auth.guard.ts`

```typescript
// NestJS
import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
// Password
import { AuthGuard } from '@nestjs/passport';
// Decorators
import { IS_PUBLIC_KEY } from '../decorators/is-public.decorator';
// Error Handling
import { UnauthorizedError } from '../errors/unauthorized.error';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext): Promise<boolean> | boolean {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const canActivate = super.canActivate(context);

    if (typeof canActivate === 'boolean') {
      return canActivate;
    }

    const canActivatePromise = canActivate as Promise<boolean>;

    return canActivatePromise.catch((error) => {
      if (error instanceof UnauthorizedError) {
        throw new UnauthorizedException(error.message);
      }

      throw new UnauthorizedException();
    });
  }
}
```

#### `src/auth/strategies/local.strategy.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' });
  }

  validate(email: string, password: string) {
    return this.authService.validateUser(email, password);
  }
}
```

#### `src/auth/guards/local-auth.guard.ts`

```typescript
import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {
  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }

  handleRequest(err, user) {
    if (err || !user) {
      throw new UnauthorizedException(err?.message);
    }

    return user;
  }
}
```

#### Importando tudo no `AppModule`

```typescript
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';
import { PrismaModule } from './prisma/prisma.module';
import { UserModule } from './user/user.module';

@Module({
  imports: [PrismaModule, UserModule, AuthModule],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
  ],
})
export class AppModule {}
```

#### Diretório `src/auth/models`

##### `src/auth/models/AuthRequest.ts`

```typescript
import { Request } from 'express';
import { User } from '../../user/entities/user.entity';

export interface AuthRequest extends Request {
  user: User;
}
```

##### `src/auth/models/LoginRequestBody.ts`

```typescript
import { IsEmail, IsString } from 'class-validator';

export class LoginRequestBody {
  @IsEmail()
  email: string;

  @IsString()
  password: string;
}
```

##### `src/auth/models/UserFromJwt.ts`

```typescript
export class UserFromJwt {
  id: number;
  email: string;
  name: string;
}
```

##### `src/auth/models/UserPayload.ts`

```typescript
export interface UserPayload {
  sub: number;
  email: string;
  name: string;
  iat?: number;
  exp?: number;
}
```

##### `src/auth/models/UserToken.ts`

```typescript
export interface UserToken {
  access_token: string;
}
```

#### Decorators: diretório `src/auth/decorators`

##### `src/auth/decorators/current-user.decorator.ts`

```typescript
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from 'src/user/entities/user.entity';
import { AuthRequest } from '../models/AuthRequest';

export const CurrentUser = createParamDecorator(
  (data: unknown, context: ExecutionContext): User => {
    const request = context.switchToHttp().getRequest<AuthRequest>();

    return request.user;
  },
);
```

##### `src/auth/decorators/is-public.decorator.ts`

```typescript
import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';
export const IsPublic = () => SetMetadata(IS_PUBLIC_KEY, true);
```

#### Tratamento de erros: diretório `src/auth/errors`

##### `src/auth/errors/unauthorized.error.ts`

```typescript
export class UnauthorizedError extends Error {}
```

### Ativando validação de dados para o Login

#### `src/auth/middlewares/login-validation.middleware.ts`

```typescript
import {
  BadRequestException,
  Injectable,
  NestMiddleware,
} from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';
import { LoginRequestBody } from '../models/LoginRequestBody';
import { validate } from 'class-validator';

@Injectable()
export class LoginValidationMiddleware implements NestMiddleware {
  async use(req: Request, res: Response, next: NextFunction) {
    const body = req.body;

    const loginRequestBody = new LoginRequestBody();
    loginRequestBody.email = body.email;
    loginRequestBody.password = body.password;

    const validations = await validate(loginRequestBody);

    if (validations.length) {
      throw new BadRequestException(
        validations.reduce((acc, curr) => {
          return [...acc, ...Object.values(curr.constraints)];
        }, []),
      );
    }

    next();
  }
}
```

## Requisições

### Criação de usuário

> **❗ Importante ❗**
>
> Para criar um usuário, certifique-se de liberar o endpoint antes com o `decorator` `@IsPublic()`.
>
> Caso a criação de usuários da sua aplicação seja restrita, remova o `decorator` `IsPublic()`, pois as próximas criações deverão ser autenticadas por um usuário já existente.

**Endpoint:** `/user`

**Method:** `POST`

**Request Body:**

```json
{
    "email": "paulo@salvatore.tech",
    "password": "Abc@123",
    "name": "Paulo Salvatore"
}
```

**Response Body (Status 201):**

```json
{
    "id": 1,
    "email": "paulo@salvatore.tech",
    "name": "Paulo Salvatore"
}
```

### Realizando o login

**Endpoint:** `/login`

**Method:** `POST`

**Request Body:**

```json
{
    "email": "paulo@salvatore.tech",
    "password": "Abc@123"
}
```

**Response Body (Status 200):**

```json
{
    "access_token": "JWT token gerado"
}
```

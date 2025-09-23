# Student Management System - Multi-Module Architecture

A Spring Boot multi-module application for student management with separate authentication and student management modules.

## 🏗️ Architecture Overview

This project is structured as a multi-module Maven project with two independent modules:

```
student-management-system/
├── pom.xml                    # Parent POM
├── auth-module/               # Authentication & JWT Module
│   ├── pom.xml
│   └── src/main/java/com/example/auth/
│       ├── controller/        # Auth REST controllers
│       ├── model/            # User, Role, RefreshToken entities
│       ├── service/          # Authentication services
│       ├── repository/       # User & token repositories
│       ├── config/           # Security configurations
│       ├── dto/              # Auth DTOs
│       ├── filter/           # JWT filters
│       └── util/             # JWT utilities
└── student-module/           # Student Management Module
    ├── pom.xml
    └── src/main/java/com/example/student/
        ├── controller/       # Student REST & Web controllers
        ├── model/           # Student entity
        ├── service/         # Student business logic
        ├── repository/      # Student data access
        ├── exception/       # Custom exceptions & handlers
        └── resources/templates/students/  # Thymeleaf templates
```

## 🚀 Modules

### 1. Auth Module (Port: 8082)
**Purpose**: Handles user authentication, JWT token management, and security

**Features**:
- User registration and login
- JWT access and refresh token management
- Role-based authentication (STUDENT, ADMIN, TEACHER)
- Password encryption with BCrypt
- Token validation and refresh endpoints

**Key Endpoints**:
- `POST /auth/register` - Register new user
- `POST /auth/login` - User login
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - User logout
- `GET /auth/profile` - Get user profile
- `GET /auth/validate` - Validate token

### 2. Student Module (Port: 8083)
**Purpose**: Manages student information with full CRUD operations

**Features**:
- Complete student CRUD operations
- Web interface with Thymeleaf templates
- REST API for external integrations
- Search functionality
- Data validation and error handling
- Responsive web forms

**Key Endpoints**:

**REST API**:
- `GET /api/students` - Get all students
- `POST /api/students` - Create student
- `GET /api/students/{id}` - Get student by ID
- `PATCH /api/students/{id}` - Update student
- `DELETE /api/students/{id}` - Delete student
- `GET /api/students/search?name={name}` - Search students

**Web Interface**:
- `GET /web/students` - Student list page
- `GET /web/students/new` - Create student form
- `GET /web/students/{id}` - Student details page
- `GET /web/students/{id}/edit` - Edit student form
- `GET /web/students/search` - Search form

## 🛠️ Technology Stack

- **Framework**: Spring Boot 3.5.5
- **Language**: Java 23
- **Database**: MySQL 8.0
- **Security**: Spring Security + JWT
- **Template Engine**: Thymeleaf
- **Build Tool**: Maven
- **Architecture**: Multi-module (not microservices)

## 📋 Prerequisites

- Java 23 or higher
- Maven 3.6+
- MySQL 8.0+
- IDE (IntelliJ IDEA, Eclipse, VS Code)

## 🚀 Getting Started

### 1. Database Setup
```sql
CREATE DATABASE student_db;
```

### 2. Configuration
Update database credentials in both modules' `application.properties`:
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/student_db
spring.datasource.username=your_username
spring.datasource.password=your_password
```

### 3. Build the Project
```bash
# Build all modules
mvn clean install

# Or build individual modules
cd auth-module && mvn clean install
cd student-module && mvn clean install
```

### 4. Run the Modules

**Option 1: Run both modules simultaneously**
```bash
# Terminal 1 - Auth Module
cd auth-module
mvn spring-boot:run

# Terminal 2 - Student Module  
cd student-module
mvn spring-boot:run
```

**Option 2: Run individual modules**
```bash
# Run only student module (for basic functionality)
cd student-module
mvn spring-boot:run
```

### 5. Access the Applications

**Student Module**:
- Web Interface: http://localhost:8083/web/students
- API Documentation: http://localhost:8083/api/students

**Auth Module**:
- API Base: http://localhost:8082/auth
- Health Check: http://localhost:8082/auth/health

## 🔧 Development Profiles

Both modules support development and production profiles:

**Development Mode** (default):
```properties
spring.profiles.active=dev
```
- Minimal security
- All endpoints accessible
- Ideal for testing

**Production Mode**:
```properties
spring.profiles.active=prod
```
- Full JWT security
- Authentication required
- Production-ready

## 📊 Database Schema

**Users Table** (Auth Module):
```sql
CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    roll_no INT UNIQUE NOT NULL,
    role ENUM('STUDENT', 'ADMIN', 'TEACHER') NOT NULL,
    account_non_expired BOOLEAN DEFAULT TRUE,
    account_non_locked BOOLEAN DEFAULT TRUE,
    credentials_non_expired BOOLEAN DEFAULT TRUE,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

**Students Table** (Student Module):
```sql
CREATE TABLE students (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    roll_no INT UNIQUE NOT NULL,
    branch VARCHAR(255) NOT NULL,
    course VARCHAR(255) NOT NULL
);
```

**Refresh Tokens Table** (Auth Module):
```sql
CREATE TABLE refresh_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(500) UNIQUE NOT NULL,
    user_id BIGINT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## 🔐 Security Features

### JWT Configuration
- **Access Token**: 30 minutes expiry
- **Refresh Token**: 30 days expiry
- **Algorithm**: HMAC SHA-256
- **Secret**: Configurable via properties

### Password Security
- **Encryption**: BCrypt with salt
- **Validation**: Minimum 6 characters
- **Storage**: Never stored in plain text

## 🧪 Testing

### API Testing with cURL

**Register User**:
```bash
curl -X POST http://localhost:8082/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "password123",
    "email": "john@example.com",
    "rollNo": 12345
  }'
```

**Create Student**:
```bash
curl -X POST http://localhost:8083/api/students \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "rollNo": 12345,
    "branch": "Computer Science",
    "course": "B.Tech"
  }'
```

## 📁 Project Structure Benefits

### ✅ **Multi-Module Advantages**:
- **Separation of Concerns**: Auth and student logic are isolated
- **Independent Development**: Teams can work on modules separately
- **Selective Deployment**: Deploy only changed modules
- **Reusability**: Auth module can be reused in other projects
- **Maintainability**: Easier to maintain and debug
- **Scalability**: Can be converted to microservices later

### ✅ **Clean Architecture**:
- **No Circular Dependencies**: Modules are independent
- **Clear Boundaries**: Well-defined module responsibilities
- **Consistent Structure**: Both modules follow same patterns
- **Easy Testing**: Modules can be tested independently

## 🔄 Migration from Monolith

This project was restructured from a monolithic application to a multi-module architecture:

**Before**: Single module with mixed concerns
**After**: Two focused modules with clear responsibilities

**Cleaned Up**:
- ❌ Removed redundant `login` package (duplicate of `auth`)
- ❌ Removed unnecessary documentation files
- ❌ Removed build artifacts (`target` directories)
- ❌ Consolidated duplicate DTOs and configurations

## 🚀 Future Enhancements

1. **API Gateway**: Add a gateway for routing between modules
2. **Service Discovery**: Implement service registry
3. **Configuration Server**: Centralized configuration management
4. **Monitoring**: Add health checks and metrics
5. **Docker**: Containerize both modules
6. **CI/CD**: Automated build and deployment pipelines

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes in appropriate module
4. Test both modules
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License.

## 📞 Support

For questions or issues:
- Create an issue in the repository
- Check module-specific logs
- Verify database connectivity
- Ensure correct ports are available (8082, 8083)

---

**Happy Coding! 🎉**

# Spring Security Basics

This project demonstrates the basics of implementing Spring Security in a Spring Boot application with a PostgreSQL database. It covers user authentication, role-based authorization, custom error handling, and more.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Getting Started](#getting-started)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Adding Users to Database](#adding-users-to-database)
- [Deployment](#deployment)
- [License](#license)

## Introduction

This project is designed to teach the fundamentals of Spring Security. We will cover how to set up security configurations, handle user roles, and protect endpoints. Additionally, we'll use a PostgreSQL database for storing user credentials.

## Features

- User authentication and role-based authorization
- Secure password storage using bcrypt
- Custom login and error pages
- In-memory and database-backed user details service

## Getting Started

Follow these instructions to get a copy of the project up and running on your local machine for development and testing purposes.

## Prerequisites

- Java 17 or higher
- Maven
- PostgreSQL
- IntelliJ IDEA or any preferred IDE

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/patzu/spring_security_basic.git
   cd spring_security_basic
   ```

2. Set up PostgreSQL and create a database:
   ```sql
   CREATE DATABASE springsecuritybasic;
   ```

3. Update the database configuration in `src/main/resources/application.properties`:
   ```properties
   spring.datasource.url=jdbc:postgresql://localhost:5432/springsecuritybasic
   spring.datasource.username=postgres
   spring.datasource.password=123456

   spring.jpa.hibernate.ddl-auto=update
   spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect

   spring.thymeleaf.enabled=true
   spring.thymeleaf.cache=false
   spring.thymeleaf.prefix=classpath:/templates/
   spring.thymeleaf.suffix=.html

   spring.web.resources.static-locations=classpath:/static/

   server.error.path=/error
   server.error.whitelabel.enabled=false
   ```

4. Build and run the application:
   ```bash
   mvn clean install
   mvn spring-boot:run
   ```

## Configuration

Configure the security settings in `SecurityConfiguration.java`. This file defines the security filter chain, form login settings, and more.

## Adding Users to Database

To ensure that we have users with appropriate roles in our application, we need to manually add two records to the `myuser` table in the PostgreSQL database. This step is crucial as it allows us to test the authentication and authorization functionalities of our Spring Boot application.

After configuring the database and ensuring that the application can connect to it, follow these steps to add the records:

1. Open IntelliJ IDEA.
2. Navigate to the Database tab.
3. Connect to your PostgreSQL database.
4. Execute the following SQL commands to insert the records into the `myuser` table:
   ```sql
   INSERT INTO myuser (id, username, password, roles) VALUES 
   (1000, 'jhon', '$2a$12$JRP8vS.dBHiGYBAkT69K9.UEt/F1P09jYVhUAAfwTJMhiKK8HjLxu', 'USER'),
   (1001, 'jane', '$2a$12$JRP8vS.dBHiGYBAkT69K9.UEt/F1P09jYVhUAAfwTJMhiKK8HjLxu', 'ADMIN,USER');
   ```
   Note: The passwords were generated using an online bcrypt converter for the plaintext password "123".

## Deployment

After successfully building and testing your Spring Boot application, it's time to deploy it so that others can access it. You can deploy your application using various platforms, but a highly recommended and user-friendly option is [Railway](https://railway.app/?referralCode=VjB8-C). Railway provides a seamless deployment process with minimal configuration required. Simply connect your GitHub repository, and Railway will handle the rest, ensuring your application is up and running in no time.

## License

This project is licensed under the MIT License.

---

You can find the complete source code for this project on GitHub at the following URL: [https://github.com/patzu/spring_security_basic](https://github.com/patzu/spring_security_basic).

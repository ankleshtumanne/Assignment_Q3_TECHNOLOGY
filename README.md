# Employee Management System

# Overview

The Employee Management System is a web application built using ASP.NET that allows users to register and log in. The system implements authentication and authorization, ensuring that employees can access only their data, while admins have full control over all employee records.

Features

User Authentication & Authorization

Users can register and log in.

Passwords are securely hashed.

JWT-based authentication.

Role-Based Access Control (RBAC)

Admin: Can view, update, delete, and manage all employee data.

Employee: Can only view their own details.

Employee Management

Create new employee records.

Update employee details.

Delete employee records.

Fetch all employees (Admin only) or fetch by ID.

Secure API Endpoints

Protected routes using authentication middleware.

Role-based authorization to prevent unauthorized access.

Technologies Used

Backend: ASP.NET Core

Database: Entity Framework (EF Core) with SQL Server

Authentication: JWT (JSON Web Tokens)

Authorization: Role-based access control

Design Principles: SOLID Principles, Clean Architecture

API Endpoints

Authentication

POST /api/auth/register - Register a new user (Admin or Employee)

POST /api/auth/login - Login and receive a JWT token

Employee Management (Admin Only)

GET /api/employees - Get all employees

GET /api/employees/{id} - Get employee by ID

POST /api/employees - Create a new employee

PUT /api/employees/{id} - Update an employee

DELETE /api/employees/{id} - Delete an employee

Employee Self-Access

GET /api/employees/me - Employee can view their own details

Installation & Setup

Clone the repository:

git clone https://github.com/yourusername/employee-management.git
cd employee-management

Install dependencies:

dotnet restore

Set up the database (ensure SQL Server is running):

dotnet ef database update

Run the application:#
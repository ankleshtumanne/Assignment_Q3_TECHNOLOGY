using Assignment_Q3_2.DTOs;
using Assignment_Q3_2.Models;
using Assignment_Q3_2.Repositories;


using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
namespace Assignment_Q3_2.Services
{
    public class EmployeeService : IEmployeeService
    {
        private readonly IEmployeeRepository _employeeRepository;

        public EmployeeService(IEmployeeRepository employeeRepository)
        {
            _employeeRepository = employeeRepository;
        }

        // Get all employees
        public async Task<IEnumerable<EmployeeDTO>> GetAllEmployeesAsync()
        {
            var employees = await _employeeRepository.GetAllEmployeesAsync();
            return employees.Select(e => new EmployeeDTO
            {
                Id = e.Id,
                FirstName = e.FirstName,
                LastName = e.LastName,
                Email = e.Email,
                DateOfBirth = e.DateOfBirth,
                Position = e.Position,
                Salary = e.Salary
            });
        }

        // Get an employee by ID
        public async Task<EmployeeDTO> GetEmployeeByIdAsync(int id)
        {
            var employee = await _employeeRepository.GetEmployeeByIdAsync(id);
            if (employee == null) return null;

            return new EmployeeDTO
            {
                Id = employee.Id,
                FirstName = employee.FirstName,
                LastName = employee.LastName,
                Email = employee.Email,
                DateOfBirth = employee.DateOfBirth,
                Position = employee.Position,
                Salary = employee.Salary
            };
        }

        // Create a new employee
        public async Task<EmployeeDTO> CreateEmployeeAsync(CreateEmployeeDTO createEmployeeDTO)
        {
            var employee = new Employee
            {
                FirstName = createEmployeeDTO.FirstName,
                LastName = createEmployeeDTO.LastName,
                Email = createEmployeeDTO.Email,
                DateOfBirth = createEmployeeDTO.DateOfBirth,
                Position = createEmployeeDTO.Position,
                Salary = createEmployeeDTO.Salary
            };

            await _employeeRepository.AddEmployeeAsync(employee);

            return new EmployeeDTO
            {
                Id = employee.Id,
                FirstName = employee.FirstName,
                LastName = employee.LastName,
                Email = employee.Email,
                DateOfBirth = employee.DateOfBirth,
                Position = employee.Position,
                Salary = employee.Salary
            };
        }

        // Update an existing employee
        public async Task<bool> UpdateEmployeeAsync(int id, UpdateEmployeeDTO updateEmployeeDTO)
        {
            var existingEmployee = await _employeeRepository.GetEmployeeByIdAsync(id);
            if (existingEmployee == null) return false;

            existingEmployee.FirstName = updateEmployeeDTO.FirstName;
            existingEmployee.LastName = updateEmployeeDTO.LastName;
            existingEmployee.Position = updateEmployeeDTO.Position;
            existingEmployee.Salary = updateEmployeeDTO.Salary;

            await _employeeRepository.UpdateEmployeeAsync(existingEmployee);
            return true;
        }

        // Delete an employee by ID
        public async Task<bool> DeleteEmployeeAsync(int id)
        {
            var exists = await _employeeRepository.EmployeeExistsAsync(id);
            if (!exists) return false;

            await _employeeRepository.DeleteEmployeeAsync(id);
            return true;
        }

    }
}

using Assignment_Q3_2.Models;

namespace Assignment_Q3_2.Repositories
{
    public interface IEmployeeRepository
    {
       
            Task<IEnumerable<Employee>> GetAllEmployeesAsync();
            Task<Employee> GetEmployeeByIdAsync(int id);
            Task AddEmployeeAsync(Employee employee);
            Task UpdateEmployeeAsync(Employee employee);
            Task DeleteEmployeeAsync(int id);
            Task<bool> EmployeeExistsAsync(int id);
        
    }
}

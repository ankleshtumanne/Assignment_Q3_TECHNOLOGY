using Assignment_Q3_2.DTOs;
using Assignment_Q3_2.Services;
using Microsoft.AspNetCore.Authorization;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
//using EmployeeManagement.DTOs;
//using EmployeeManagement.Services;
using Microsoft.OpenApi.Models;
using System.Collections.Generic;
using System.Threading.Tasks;
using static Assignment_Q3_2.Services.IEmployeeService;
namespace Assignment_Q3_2.Controllers
{
    //[Route("api/employees")]
    [Route("api/[controller]")]
    [ApiController]
    //[Authorize]
    public class EmployeeController : ControllerBase
    {
        private readonly Services.IEmployeeService _employeeService;

        public EmployeeController(IEmployeeService employeeService)
        {
            _employeeService = employeeService;
        }

        // GET: api/employees (Fetch all employees)
        [HttpGet]
        [Authorize(Roles = "admin")]
        public async Task<ActionResult<IEnumerable<EmployeeDTO>>> GetAllEmployees()
        {
            var employees = await _employeeService.GetAllEmployeesAsync();
            return Ok(employees);
        }

        // GET: api/employees/{id} (Fetch a single employee by ID)
        //[HttpGet("{id}")]
        //[Authorize(Roles = "admin")]
        //public async Task<ActionResult<EmployeeDTO>> GetEmployeeById(int id)
        //{
        //    var employee = await _employeeService.GetEmployeeByIdAsync(id);
        //    if (employee == null)
        //    {
        //        return NotFound(new { message = "Employee not found" });
        //    }
        //    return Ok(employee);
        //}
        [HttpGet("{id}")]
        [Authorize(Roles = "admin")]
        public async Task<ActionResult<EmployeeDTO>> GetEmployeeById(int id)
        {
            var user = HttpContext.User;
            var roles = user.Claims.Where(c => c.Type == "role").Select(c => c.Value).ToList();

            Console.WriteLine("User Roles: " + string.Join(", ", roles)); // Debugging roles

            if (!user.IsInRole("admin"))
            {
                return Forbid("You are not authorized to access this resource.");
            }

            var employee = await _employeeService.GetEmployeeByIdAsync(id);
            if (employee == null)
            {
                return NotFound(new { message = "Employee not found" });
            }

            return Ok(employee);
        }

        // POST: api/employees (Create a new employee)
        [HttpPost]
        
        public async Task<ActionResult<EmployeeDTO>> CreateEmployee([FromBody] CreateEmployeeDTO createEmployeeDTO)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var newEmployee = await _employeeService.CreateEmployeeAsync(createEmployeeDTO);
            return CreatedAtAction(nameof(GetEmployeeById), new { id = newEmployee.Id }, newEmployee);
        }

        // PUT: api/employees/{id} (Update an existing employee)
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateEmployee(int id, [FromBody] UpdateEmployeeDTO updateEmployeeDTO)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var success = await _employeeService.UpdateEmployeeAsync(id, updateEmployeeDTO);
            if (!success)
            {
                return NotFound(new { message = "Employee not found" });
            }

            return NoContent();
        }

        // DELETE: api/employees/{id} (Delete an employee by ID)
        [HttpDelete("{id}")]
        [Authorize(Roles = "admin")]

        public async Task<IActionResult> DeleteEmployee(int id)
        {
            var success = await _employeeService.DeleteEmployeeAsync(id);
            if (!success)
            {
                return NotFound(new { message = "Employee not found" });
            }

            return NoContent();
        }

        
    }
}

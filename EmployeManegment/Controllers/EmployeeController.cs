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
    [Authorize]
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

        [HttpGet("{id}")]
        [Authorize(Roles = "admin,user")]
        public async Task<ActionResult<EmployeeDTO>> GetEmployeeById(int id)
        {
            // Get the current logged-in user's username
            var currentUsername = User.Identity.Name;

            // Get the employee data
            var employee = await _employeeService.GetEmployeeByIdAsync(id);
            if (employee == null)
            {
                return NotFound(new { message = "Employee not found" });
            }

            //  admin,  can see everything
            if (User.IsInRole("admin"))
            {
                return Ok(employee);
            }
            // If regular user, they can only see their own data
            else
            {
                //  if the employee email matches the logged-in user's username
                
                if (employee.Email != currentUsername)
                {
                    return StatusCode(403, new { message = "You can only view your own information" });
                }
                //1 more way
                //if (employee.Email != currentUsername)
                //{
                //    return Unauthorized(new { message = "You can only view your own information" });
                //}

                // Return limited details for the user's own data
                return Ok(new
                {
                    Id = employee.Id,
                    FirstName = employee.FirstName,
                    LastName = employee.LastName,
                    Email = employee.Email,
                    Position = employee.Position
                    // Exclude sensitive data like salary
                });
            }
        }
        //[HttpGet("{id}")]
        //[Authorize(Roles = "admin,user")]
        //public async Task<ActionResult<EmployeeDTO>> GetEmployeeById(int id)
        //{
        //    var employee = await _employeeService.GetEmployeeByIdAsync(id);
        //    if (employee == null)
        //    {
        //        return NotFound(new { message = "Employee not found" });
        //    }

        //    // If you need different behavior based on role
        //    if (User.IsInRole("admin"))
        //    {
        //        // Return full details for admin
        //        return Ok(employee);
        //    }
        //    else
        //    {
        //        // Return limited details for regular users
        //        return Ok(new
        //        {
        //            Id = employee.Id,
        //            FirstName = employee.FirstName,
        //            LastName = employee.LastName,
        //            Position = employee.Position
        //            // Exclude sensitive data like salary
        //        });
        //    }
        //}
        //[HttpGet("{id}")]
        //[Authorize(Roles = "admin,user")]
        //public async Task<ActionResult<EmployeeDTO>> GetEmployeeById(int id)
        //{
        //    var user = HttpContext.User;


        //    foreach (var claim in user.Claims)
        //    {
        //        Console.WriteLine($"Claim Type: {claim.Type}, Value: {claim.Value}");
        //    }

        //    if (!user.IsInRole("admin"))
        //    {
        //        return Forbid("You are not authorized to access this resource.");
        //    }

        //    var employee = await _employeeService.GetEmployeeByIdAsync(id);
        //    if (employee == null)
        //    {
        //        return NotFound(new { message = "Employee not found" });
        //    }

        //    return Ok(employee);
        //}



        // POST: api/employees (Create a new employee)
        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult<EmployeeDTO>> CreateEmployee([FromBody] CreateEmployeeDTO createEmployeeDTO)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var newEmployee = await _employeeService.CreateEmployeeAsync(createEmployeeDTO);
            return CreatedAtAction(nameof(GetEmployeeById), new { id = newEmployee.Id }, newEmployee);
        }

        [HttpPut("{id}")]
        [Authorize(Roles = "admin")] // Add admin role requirement
        public async Task<IActionResult> UpdateEmployee(int id, [FromBody] UpdateEmployeeDTO updateEmployeeDTO)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var success = await _employeeService.UpdateEmployeeAsync(id, updateEmployeeDTO);
                if (!success)
                {
                    return NotFound(new { message = $"Employee with ID {id} not found" });
                }

                return Ok(new { message = "Employee updated successfully" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = $"Error updating employee: {ex.Message}" });
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = "admin")]
        public async Task<IActionResult> DeleteEmployee(int id)
        {
            try
            {
                var success = await _employeeService.DeleteEmployeeAsync(id);
                if (!success)
                {
                    return NotFound(new { message = $"Employee with ID {id} not found" });
                }

                return Ok(new { message = "Employee deleted successfully" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = $"Error deleting employee: {ex.Message}" });
            }
        }
        

       

    }
}

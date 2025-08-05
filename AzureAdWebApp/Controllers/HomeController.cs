using AzureAdWebApp.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;
using System.Text.Json;

namespace AzureAdWebApp.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            if (!User.IsInRole("Admin"))
            {
                return RedirectToAction("CustomAccessDenied");
            }
            ViewBag.Message = "Welcome to the internal company portal with role"+ ViewBag.Role ;
            return View();
        }

        public IActionResult About()
        {
            return View();
        }

        public IActionResult Contact()
        {
            return View();
        }

        [AllowAnonymous]
        public IActionResult Public()
        {
            return View();
        }
        //[Authorize(Roles = "Manager")]
        public IActionResult Privacy()
        {
            if (!User.IsInRole("Manager"))
            {
                return RedirectToAction("CustomAccessDenied");
            }
            return View();
        }
        //[Authorize(Roles = "Admin")]
        public IActionResult AdminOnlyPage()
        {
            if (!User.IsInRole("Admin"))
            {
                return RedirectToAction("CustomAccessDenied");
            }
            return View();
        }

        public IActionResult CustomAccessDenied()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}

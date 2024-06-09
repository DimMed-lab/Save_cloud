using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;

namespace Save_cloud.Attributes
{
    public class MultipartFormDataAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext ctx)
        {
            var r = ctx.HttpContext.Request;
            if (r.HasFormContentType && r.ContentType.StartsWith("multipart/form-data"))
                return;

            ctx.Result = new StatusCodeResult(StatusCodes.Status415UnsupportedMediaType);
        }
    }
}

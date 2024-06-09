using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Save_cloud.Attributes
{
    public class DisableModelBindingAttribute : Attribute
    {
        public void OnResourceExecuting(ResourceExecutingContext ctx)
        {
            var f = ctx.ValueProviderFactories;
            f.RemoveType<FormValueProviderFactory>();
            f.RemoveType<FormFileValueProviderFactory>();
            f.RemoveType<JQueryFormValueProviderFactory>();
        }
    }
}

# Import necessary Django modules for handling HTTP requests and render templates
from django.http import HttpResponseRedirect
from django.shortcuts import redirect, render

# Import custom module for SSL-related functionality
from .ssl import get_cert_name_from_serial

# Import form for search functionality
from .forms import SearchForm

# View function to display certificate details based on serial number
def certificate_view(request):
    serial = request.GET.get("serial", None) # Extract serial number from query parameters
    cert = get_cert_name_from_serial(serial) # Retrieve certificate information based on serial number
     # Render the detail template with certificate information
    return render(request, "detail.html", context={"cert": cert})


def search_view(request): # View function to handle search functionality
    if request.method == "POST": # If the request method is POST, then process the search form
        form = SearchForm(request.POST) # Creating a form with submitted data
        if form.is_valid(): # Check to see if the submitted data is valid
            print(form.cleaned_data["serial"]) # Print serial number
            # Redirect to the certificate view with the serial number
            return redirect(f"/certificate/?serial={form.cleaned_data['serial']}")
    else:
        form = SearchForm()
    # Render the search template
    return render(request, "search.html", {"form": form})

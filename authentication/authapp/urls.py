from django.urls import path, include
from django.conf.urls import url
from authapp import views
# SET THE NAMESPACE!
app_name = 'authapp'
# Be careful setting the name to just /login use userlogin instead!
urlpatterns = [
    url(r'^register/$',views.register,name='register'),
    url(r'^user_login/$',views.user_login,name='user_login'),
    #url(r'^sent/', views.activation_sent_view, name="activation_sent"),
    #url(r'^activate/<slug:uidb64>/<slug:token>/', views.activate, name='activate'),
]
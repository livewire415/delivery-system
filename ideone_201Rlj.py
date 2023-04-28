# your code goes herefrom django.shortcuts import # Import Django libraries and models
from django.contrib.auth.models import User
from django.db import models

# Create a model for user profiles
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=20)
    address = models.CharField(max_length=200)

# Create a model for orders
class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    order_number = models.CharField(max_length=50)
    delivery_address = models.CharField(max_length=200)
    status = models.CharField(max_length=20)

# Create a view for order placement
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages

@login_required
def place_order(request):
    if request.method == 'POST':
        delivery_address = request.POST['delivery_address']
        order_number = '1234' # Generate unique order number
        user = request.user
        order = Order(user=user, order_number=order_number, delivery_address=delivery_address, status='Pending')
        order.save()
        messages.success(request, 'Your order has been placed!')
        return redirect('order_tracking')
    return render(request, 'place_order.html')

# Create a view for order tracking
@login_required
def order_tracking(request):
    orders = Order.objects.filter(user=request.user)
    return render(request, 'order_tracking.html', {'orders': orders})
render

from django.contrib.auth import logout

from rest_framework import permissions
# Create your views here.
from django.http import HttpResponse
from rest_framework import permissions, viewsets

from RtiBenefitAdmin.models import Account
from RtiBenefitAdmin.serializers import AccountSerializer
from RtiBenefitAdmin.permissions import IsAccountOwner

from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.generic.base import TemplateView
from django.utils.decorators import method_decorator

import json
from django.contrib.auth import authenticate, login
from rest_framework import status, views
from rest_framework.response import Response
class IndexView(TemplateView):

    template_name = 'index.html'
    @method_decorator(ensure_csrf_cookie)
    def dispatch(self, *args, **kwargs):
        return super(IndexView, self).dispatch(*args, **kwargs)

class AccountViewSet(viewsets.ModelViewSet):  
    lookup_field = 'username'
    queryset = Account.objects.all()
    serializer_class = AccountSerializer
    def get_permissions(self):
        if self.request.method in permissions.SAFE_METHODS:
            return (permissions.AllowAny(),)

        if self.request.method == 'POST':            
            return (permissions.AllowAny(),)

        return (permissions.IsAuthenticated(), IsAccountOwner(),)

    def create(self, request):
        serializer = self.serializer_class(data=request.DATA)

        if serializer.is_valid():
            account = Account.objects.create_user(**request.DATA)
            account.set_password(request.DATA.get('password'))
            account.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response({
            'status': 'Bad request',
            'message': 'Account could not be created with received data.'
        }, status=status.HTTP_400_BAD_REQUEST)


class LoginView(views.APIView):
    def post(self, request, format=None):
        data = json.loads(request.body)

        email = data.get('email', None)
        password = data.get('password', None)

        account = authenticate(email=email, password=password)

        if account is not None:
            if account.is_active:
                login(request, account)

                serialized = AccountSerializer(account)

                return Response(serialized.data)
            else:
                return Response({
                    'status': 'Unauthorized',
                    'message': 'This account has been disabled.'
                }, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({
                'status': 'Unauthorized',
                'message': 'Username/password combination invalid.'
            }, status=status.HTTP_401_UNAUTHORIZED)

class LogoutView(views.APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, format=None):
        logout(request)
        return Response({}, status=status.HTTP_204_NO_CONTENT)
from django.contrib.auth.hashers import make_password, check_password
from onadata.apps.usermodule.models import UserModuleProfile, UserPasswordHistory,Organizations,OrganizationDataAccess,MenuItem
from django.contrib.auth.models import User
from django import forms
from datetime import datetime, timedelta


class UserForm(forms.ModelForm):
    password = forms.CharField(label='Create a password',widget=forms.PasswordInput(),min_length=8)
    password_repeat = forms.CharField(label='Confirm your password',widget=forms.PasswordInput())
    email = forms.EmailField(required=True)
    username = forms.CharField(help_text='',max_length=10,widget=forms.TextInput(attrs={'pattern': '[a-z_0-9]+','title':'only lowercase letter, numbers and underscore(_) is allowed. example: user_2009'}))

    def clean_password_repeat(self):
        password1 = self.cleaned_data.get('password')
        password2 = self.cleaned_data.get('password_repeat')

        if password1 and password1!=password2:
            raise forms.ValidationError('Passwords Do not match')
        return self.cleaned_data

    class Meta:
        model = User
        # fields = ('username', 'email', 'password','user_permissions','is_staff','is_active','is_superuser','date_joined','groups')
        fields = ('username', 'first_name', 'last_name', 'email', 'password') # ,'is_superuser' 'date_joined',


class UserEditForm(forms.ModelForm):
    email = forms.EmailField(required=True)
    username = forms.CharField(help_text='',max_length=10)

    class Meta:
        model = User
        fields = ('username','first_name', 'last_name', 'email') # ,'is_superuser','date_joined'
        
    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super(UserEditForm, self).__init__(*args, **kwargs)
        self.fields['username'].widget.attrs['readonly'] = 'true'
    

class UserProfileForm(forms.ModelForm):
    admin = forms.BooleanField(label="Make this User Admin",widget=forms.CheckboxInput(),required=False)
    employee_id = forms.CharField(label="Employee Id ")
    organisation_name = forms.ModelChoiceField(label='Organisation Name',required=True,queryset=Organizations.objects.all(),empty_label="Select an Organization")
    country = forms.CharField(label="Country")
    position = forms.CharField(label="Position")

    # expired = forms.DateTimeField(label="Expiry Date",required=False,initial=datetime.now()+ timedelta(days=90))

    class Meta:
        model = UserModuleProfile
        fields = ('admin','employee_id','organisation_name','country','position',)

    def __init__(self, *args, **kwargs):
        admin_check = kwargs.pop('admin_check', False)
        super(UserProfileForm, self).__init__(*args, **kwargs)
        if not admin_check:
            del self.fields['admin']


class OrganizationForm(forms.ModelForm):
    organization = forms.CharField(label='Organization',required=True)
    class Meta:
        model = Organizations
        fields = ('organization',)


class OrganizationDataAccessForm(forms.ModelForm):
    observer_organization = forms.ModelChoiceField(label='Observer Organization',required=True,queryset=Organizations.objects.all(),empty_label="Select an Organization")
    observable_organization = forms.ModelChoiceField(label='Can view data of Organization',required=True,queryset=Organizations.objects.all(),empty_label="Select an Organization")
    class Meta:
        model = OrganizationDataAccess
        fields = ('observer_organization','observable_organization')


class ChangePasswordForm(forms.Form):
    username = forms.CharField(label="Username",required=True)
    old_password = forms.CharField(label="Old",required=True,widget=forms.PasswordInput(),min_length=8)
    new_password = forms.CharField(label="New",required=True,widget=forms.PasswordInput(),min_length=8)
    retype_new_password = forms.CharField(label="Retype new",required=True,widget=forms.PasswordInput())
    def clean_retype_new_password(self):
        old_password = self.cleaned_data.get('old_password')
        new_password = self.cleaned_data.get('new_password')
        retype_new_password = self.cleaned_data.get('retype_new_password')
        username = self.cleaned_data.get('username')

        if old_password and new_password == old_password:
            raise forms.ValidationError('New Password Cannot be same as old password')

        if new_password and new_password!=retype_new_password:
            raise forms.ValidationError('Passwords Do not match')

        # check password history (last 25) if it already existed before
        #get current user id
        try:
            current_user_id = User.objects.get(username=username).pk
        except User.DoesNotExist:
            raise forms.ValidationError('Username you entered is incorrect')
        # get list of last 24 password
        count_unusable_recent_password = 24
        password_list = UserPasswordHistory.objects.filter(user_id=current_user_id).order_by('-date').values('password')[:count_unusable_recent_password][::-1]

        for i in password_list:
            flag = check_password(new_password,i['password'])
            if(flag):
                raise forms.ValidationError('You cannot reuse your last '+str(count_unusable_recent_password)+ 'password as your new password')

        # UserModuleProfile.objects.filter(position='Junior Software Engineer').order_by('-id').values()[:3][::-1]
        # UserPasswordHistory.objects.filter(user_id=5).order_by('-date').values()[:2][::-1]
        return self.cleaned_data


    def __init__(self, *args, **kwargs):
        logged_in_user = kwargs.pop('logged_in_user', None)
        super(ChangePasswordForm, self).__init__(*args, **kwargs)
        if logged_in_user:
            self.fields['username'].initial = logged_in_user


class ResetPasswordForm(forms.Form):
    new_password = forms.CharField(label="New",required=True,widget=forms.PasswordInput(),min_length=8)
    retype_new_password = forms.CharField(label="Retype new",required=True,widget=forms.PasswordInput())
    def clean_retype_new_password(self):
        new_password = self.cleaned_data.get('new_password')
        retype_new_password = self.cleaned_data.get('retype_new_password')
        
        if new_password and new_password!=retype_new_password:
            raise forms.ValidationError('Passwords Do not match')

        return self.cleaned_data   
        

class MenuForm(forms.ModelForm):
    title = forms.CharField(label="Title",required=True)
    url = forms.CharField(label="Url",required=True)
    list_class = forms.CharField(label="Menu List Class")
    icon_class = forms.CharField(label="Menu Icon Class")
    parent_menu = forms.ModelChoiceField(label='Parent Menu',required=False,queryset=MenuItem.objects.all(),empty_label="Parent Menu")

    class Meta:
        model = MenuItem
        fields = ('title','url','list_class','icon_class','parent_menu')

    
    
    
    

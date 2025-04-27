from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class RegisterForm(UserCreationForm):
    username = forms.CharField(
        max_length=20,
        required=True,
        help_text='必填。最多20个字符。只能包含字母、数字和@/./+/-/_。',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': '请输入用户名'})
    )
    
    class Meta:
        model = User
        fields = ('username', 'password1', 'password2')
        
    def __init__(self, *args, **kwargs):
        super(RegisterForm, self).__init__(*args, **kwargs)
        # 添加Bootstrap类
        self.fields['password1'].widget.attrs.update({'class': 'form-control', 'placeholder': '请输入密码'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control', 'placeholder': '请再次输入密码'})
        
        # 修改帮助文本
        self.fields['password1'].help_text = '密码不能与个人信息太相似，至少包含8个字符，不能是常见密码，且不能全为数字。'
        self.fields['password2'].help_text = '请再次输入相同的密码，以进行确认。' 
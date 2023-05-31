from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin


# Custom user manager
class UserManager(BaseUserManager):
  def create_user(self, email, name, tc, password=None, password2=None):
    if not email:
      raise ValueError('Users must have an email address')
    
    user = self.model(
      email=self.normalize_email(email),
      name=name, tc=tc
    )
    user.set_password(password)
    user.save(using=self._db)
    return user
  
  def create_superuser(self, email, name, tc, password=None, password2=None):
    user = self.create_user(
      email=self.normalize_email(email),
      name=name, tc=tc
    )
    user.is_admin = True
    user.save(using=self._db)
    return user

# Custom user Model
class User(AbstractBaseUser):
  email = models.EmailField(verbose_name='Email', max_length=60, unique=True)
  name = models.CharField(verbose_name='Name', max_length=60)
  is_active = models.BooleanField(default=True)
  is_admin = models.BooleanField(default=False)
  tc = models.BooleanField()
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)

  objects = UserManager()

  USERNAME_FIELD, REQUIRED_FIELDS = 'email', ['name', 'tc']

  def __str__(self):
    return self.email
  
  def has_perm(self, perm, obj=None):
    return self.is_admin
  
  def has_module_perms(self, app_label):
    return True
  
  @property
  def is_staff(self):
    return self.is_admin
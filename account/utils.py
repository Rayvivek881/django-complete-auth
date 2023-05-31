from django.core.mail import EmailMessage
import os

class Utils:
  @staticmethod
  def send_email(data):
    email = EmailMessage(
      subject=data['email_subject'], 
      body=data['email_body'],
      from_email=os.environ.get("EMAIL_USER"),
      to=[data['to_email']])
    email.send()
# email_utils.py
from django.core.mail import send_mail  
from django.conf import settings

# def send_mail(subject, message, recipient_list, fail_silently=False):
def send_mail_custom(computer, message):
    """
    Wrapper for Django's send_mail function.
    
    Args:
        subject (str): Subject of the email.
        message (str): Body of the email.
        recipient_list (list): List of recipient email addresses.
        fail_silently (bool): Whether to fail silently or raise an exception.
    """
    # Ensure recipient_list is a list
    # if isinstance(recipient_list, str):
    #     recipient_list = recipient_list.split(',')

    # Call Django's send_mail function
    send_mail(
        f"Defender alert on {computer.hostname} / {computer.serial}",
        message,
        settings.EMAIL_FROM,  # sender email
        settings.EMAIL_TO.split(','),
        fail_silently=False,
        # fail_silently=fail_silently,
    )


                #     send_mail(
                #     f"Defender alert on {self.computer.hostname} / {self.computer.serial}",
                #     f"The antivirus mode has changed from {old_instance.antivirus_mode} to {self.antivirus_mode}.",
                #     settings.EMAIL_FROM,  # sender email
                #     # [settings.EMAIL_TO],  #   recipient email
                #     settings.EMAIL_TO.split(','),
                #     fail_silently=False,
                # )
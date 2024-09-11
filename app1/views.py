import json
import os
import re
import traceback
from datetime import datetime

from django.core.mail import send_mail

# Create your views here.
# views.py
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.http import HttpResponse, Http404
from django.conf import settings
from .models import Computer, DefenderEvent, DefenderStatus
from django.contrib.admin.views.decorators import staff_member_required


def convert_date_string(date_string):
    # Windows event logs send timestamp as a string like "/Date(1721249335619)/"
    # This coverts it to a time object.

    timestamp = int(re.search(r"\d+", date_string).group())
    naive_datetime = datetime.fromtimestamp(timestamp / 1000.0)
    aware_datetime = timezone.make_aware(naive_datetime, timezone.get_current_timezone())
    return aware_datetime


@csrf_exempt
def upload_file(request):
    if request.method == "POST" and request.FILES:
        uploaded_file = request.FILES["file"]
        # file_path = os.path.join("path", "to", "your", "directory", uploaded_file.name)
        file_path = os.path.join("uploads", uploaded_file.name)
        # file_path = uploaded_file.name
        with open(file_path, "wb+") as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)
        return JsonResponse({"message": "File uploaded successfully"})
    else:
        return JsonResponse({"error": "No file uploaded"}, status=400)


@csrf_exempt
@require_http_methods(["POST"])  # Ensures only POST requests are handled
def save_computer_data(request):
    print("asdf")
    try:
        # Parse JSON data from request body
        data = json.loads(request.body)
        print(data)
        submitted_key = data.get("key")
        expected_key = "UvijtoHetid9"

        if submitted_key != expected_key:
            return JsonResponse({"error": "Unauthorized"}, status=401)

        computer, created = Computer.objects.get_or_create(serial=data.get("serial"))

        computer.hostname = data.get("hostname")
        computer.ip = data.get("ip")
        computer.ip_public = data.get("ip_public")
        computer.os_version = data.get("os_version")
        computer.processor = data.get("processor")
        computer.ram = data.get("ram")
        computer.storage = data.get("storage")
        if data.get("console_user"): computer.console_user = data.get("console_user")
        computer.last_check_in = timezone.now()

        # Save the instance to the database
        computer.save()

        # Return a success response
        return JsonResponse({"message": "Data saved successfully"})
    except Exception as e:
        traceback.print_exc()
        # Handle exceptions and return an error response
        return JsonResponse({"error": str(e)}, status=400)


@csrf_exempt
@require_http_methods(["POST"])
def save_defender_status(request, serial):
    try:
        # Parse JSON data from request body
        data = json.loads(request.body)
        print(data)

        # Find the corresponding Computer instance
        try:
            computer = Computer.objects.get(serial=serial)
        except Computer.DoesNotExist:
            return JsonResponse({"error": "Computer not found"}, status=404)

        # Create or update the DefenderStatus instance
        defender_status, created = DefenderStatus.objects.update_or_create(
            computer=computer,
            defaults={
                "antivirus_mode": data.get("antivirus_mode"),
                "antivirus_mode_ts": data.get("antivirus_mode_ts"),
                "platform": data.get("platform"),
                "platform_ts": data.get("platform_ts"),
                "engine": data.get("engine"),
                "engine_ts": data.get("engine_ts"),
                "security_intelligence": data.get("security_intelligence"),
                "security_intelligence_ts": data.get("security_intelligence_ts"),
                "last_quick_scan": data.get("last_quick_scan"),
                "last_quick_scan_ts": data.get("last_quick_scan_ts"),
                "last_full_scan": data.get("last_full_scan"),
                "last_full_scan_ts": data.get("last_full_scan_ts"),
            },
        )

        # Return a success response
        return JsonResponse({"message": "Defender status saved successfully"})
    except Exception as e:
        traceback.print_exc()
        # Handle exceptions and return an error response
        return JsonResponse({"error": str(e)}, status=400)


@csrf_exempt
@require_http_methods(["POST"])
def save_defender_events(request, serial):
    # This function should probably be called "process defender data"
    # It no longer is just for events but also health status.

    try:
        # Parse JSON data from request body
        data = json.loads(request.body)

        # commented this out -- create the computer (get_or_create) 
        # # Find the corresponding Computer instance
        # try:
        #     computer = Computer.objects.get(serial=serial)
        # except Computer.DoesNotExist:
        #     return JsonResponse({"error": "Computer not found"}, status=404)

        computer, created = Computer.objects.get_or_create(serial=serial)

        defender_status, created = DefenderStatus.objects.get_or_create(computer=computer)

        print (f"Data-events for: {computer}")
        print(data['events'])
        for i in data["events"]:
            # print(i)
            event_id = i.get("Id")
            message = i.get("Message")
            timestamp = convert_date_string(i.get("TimeCreated"))
            severity = i.get("LevelDisplayName")[:4]

            current_ts_formatted = timezone.localtime(timezone.now()).strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"{ current_ts_formatted } / {computer.hostname} / {computer.serial} / {event_id} / evt_ts: {timestamp}"
            )

            # if event_id == 1001:
            #     print(event_id)
            #     print(message)
            #     print()

            defender_event = DefenderEvent.objects.create(
                computer=computer,
                event_id=event_id,
                message=message,
                severity=severity,
                timestamp=timestamp,
            )
            # print(defender_event)

            # Event IDs: https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus

            if event_id == 1001:  # MALWAREPROTECTION_SCAN_COMPLETED
                scan_param_pattern = r"Scan Parameters:\s*(\w+)"
                scan_param_match = re.search(scan_param_pattern, message)
                scan_param = scan_param_match.group(1) if scan_param_match else None
                if scan_param == "Quick":
                    defender_status.last_quick_scan_ts = timestamp
                if scan_param == "Full":
                    defender_status.last_full_scan_ts = timestamp

            if event_id == 1116:   # MALWAREPROTECTION_STATE_MALWARE_DETECTED
                send_mail(
                    f"Defender alert on {computer.hostname} / {computer.serial}",
                    f"Event ID: {event_id}\nTimestamp: {timestamp}\n\n{message}\n",
                    settings.EMAIL_FROM,  # sender email
                    [settings.EMAIL_TO],  #   recipient email
                    fail_silently=False,
                )
            
            
            if event_id == 1121: # Message: Event when an attack surface reduction (ASR) rule fires in block mode.
                send_mail(
                    f"Defender alert on {computer.hostname} / {computer.serial}",
                    f"Event ID: {event_id}\nTimestamp: {timestamp}\n\n{message}\n",
                    settings.EMAIL_FROM,  # sender email
                    [settings.EMAIL_TO],  #   recipient email
                    fail_silently=False,
                )

            # TODO: consider not using this. instead use the API Data from get-mpcomputerstatus which should be more accurate.
            # if event_id == 1150: # MALWAREPROTECTION_SERVICE_HEALTHY
            #     # DefenderStatus.objects.filter(computer=computer).update(antivirus_mode='active')
            #     defender_status.antivirus_mode = 'active'
            #     # defender_status.save()

            if event_id == 1151:  # MALWAREPROTECTION_SERVICE_HEALTH_REPORT
                if "Disabled" in message:
                    defender_status.antivirus_mode = "inactive"

            if event_id == 2000:  # MALWAREPROTECTION_SIGNATURE_UPDATED
                current_signature_pattern = r"Current security intelligence Version:\s*([\d\.]+)"
                current_engine_pattern = r"Current Engine Version:\s*([\d\.]+)"

                # Search for the patterns in the message
                current_signature_match = re.search(current_signature_pattern, message)
                current_engine_match = re.search(current_engine_pattern, message)

                # Extract the versions
                current_signature_version = (
                    current_signature_match.group(1) if current_signature_match else None
                )
                current_engine_version = (
                    current_engine_match.group(1) if current_engine_match else None
                )

                # timestamp is updated using the model save method.
                # DefenderStatus.objects.filter(computer=computer).update(engine=current_engine_version)
                # DefenderStatus.objects.filter(computer=computer).update(security_intelligence=current_signature_version)
                defender_status.engine = current_engine_version
                defender_status.security_intelligence = current_signature_version
                # defender_status.save()

            if event_id == 2014:
                pattern = r"update to ([\d\.]+) has succeeded"
                match = re.search(pattern, message)
                version = match.group(1)
                defender_status.platform = version

            if event_id == 3002: # MALWAREPROTECTION_RTP_FEATURE_FAILURE
                defender_status.antivirus_mode = "inactive"


            if event_id == 5001:  # MALWAREPROTECTION_RTP_DISABLED
                defender_status.antivirus_mode = "inactive"

        if len(data["events"]) > 0:
            # Update DefenderStatus.last_event_ts with the current time
            # DefenderStatus.objects.filter(computer=computer).update(last_event_ts=timezone.now())
            # defender_status, created = DefenderStatus.objects.get_or_create(computer=computer)
            defender_status.last_event_ts = timezone.now()

        # status-healthy comes in as True/False/None.
        print(f"{computer.hostname} : {data['status']['healthy']}")
        if data["status"]["healthy"] is True:
            defender_status.antivirus_mode = "active"
            print(f"{computer.hostname} sent status api of active")

        elif data["status"]["healthy"] is False:
            defender_status.antivirus_mode = "inactive"
            print(f"{computer.hostname} sent status api of inactive")

        defender_status.save()

        # Return a success response
        # return JsonResponse({"message": "Defender event saved successfully"})
        # return JsonResponse({"message": "Defender event saved successfully", "succeeded": 1})
        return JsonResponse(
            {
                "message": "Defender event saved successfully",
                "data": {
                    "computer_id": computer.serial,
                    "event_count": len(data),
                    "succeeded": 1,
                },
            }
        )
    except Exception as e:
        traceback.print_exc()
        # Handle exceptions and return an error response
        return JsonResponse({"error": str(e)}, status=400)


@staff_member_required
def view_text_file(request, serial):
    file_path = os.path.join('uploads', f'{serial}.txt')
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            response = HttpResponse(file.read(), content_type='text/plain')
            response['Content-Disposition'] = f'inline; filename={serial}.txt'
            return response
    else:
        raise Http404("File not found")
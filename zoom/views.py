from django.shortcuts import render

# Create your views here.
import jwt
import time
import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from base64 import b64encode


class ZoomIntegrationAPIView(APIView):
    """
    A single API to handle:
    1. OAuth authorization code exchange.
    2. Fetching ZAK token for the user.
    3. Generating a JWT signature for a meeting.
    """

    def post(self, request):
        # Extract input data
        authorization_code = request.data.get("code")  # OAuth authorization code
        redirect_uri = request.data.get("redirect_uri", "http://localhost:8000/oauth/callback/")
        meeting_number = request.data.get("meetingNumber")
        role = request.data.get("role", 0)  # 0 for participant, 1 for host
        expiration_seconds = request.data.get("expirationSeconds", 7200)  # Default 2 hours

        # Validate inputs
        if not authorization_code or not meeting_number:
            return Response(
                {"error": "Authorization code and meeting number are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Step 1: Exchange Authorization Code for Access Token
        client_id = settings.ZOOM_CLIENT_ID
        client_secret = settings.ZOOM_CLIENT_SECRET
        if not client_id or not client_secret:
            return Response(
                {"error": "Missing Zoom client ID or client secret in settings."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Combine client_id and client_secret for encoding
        auth_string = f"{client_id}:{client_secret}"
        auth_header = b64encode(auth_string.encode()).decode()  # Correct Base64 encoding

        token_url = "https://zoom.us/oauth/token"
        token_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": redirect_uri,
        }

        token_headers = {
            "Authorization": f"Basic {auth_header}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        # Request access token
        token_response = requests.post(token_url, data=token_data, headers=token_headers)
        if token_response.status_code != 200:
            return Response(
                {"error": "Failed to retrieve access token.", "details": token_response.json()},
                status=token_response.status_code,
            )

        token_data = token_response.json()
        access_token = token_data.get("access_token")

        # Step 2: Retrieve User Information
        user_info_url = "https://api.zoom.us/v2/users/me"
        user_info_headers = {"Authorization": f"Bearer {access_token}"}

        user_info_response = requests.get(user_info_url, headers=user_info_headers)
        if user_info_response.status_code != 200:
            return Response(
                {"error": "Failed to retrieve user information.", "details": user_info_response.json()},
                status=user_info_response.status_code,
            )

        user_id = user_info_response.json().get("id")

        # Step 3: Retrieve ZAK Token
        zak_url = f"https://api.zoom.us/v2/users/{user_id}/token?type=zak"
        zak_headers = {"Authorization": f"Bearer {access_token}"}

        zak_response = requests.get(zak_url, headers=zak_headers)
        if zak_response.status_code != 200:
            return Response(
                {"error": "Failed to retrieve ZAK token.", "details": zak_response.json()},
                status=zak_response.status_code,
            )

        zak_token = zak_response.json().get("token")

        # Step 4: Generate JWT Signature
        iat = int(time.time())
        exp = iat + expiration_seconds

        # Construct the payload ensuring all values are strings
        payload = {
            "sdkKey": str(settings.ZOOM_MEETING_SDK_KEY),
            "appKey": str(settings.ZOOM_MEETING_SDK_KEY),
            "mn": str(meeting_number),  # Ensure meeting number is a string
            "role": str(role),  # Ensure role is a string
            "iat": iat,  # No need to convert iat; it's an integer timestamp
            "exp": exp,  # No need to convert exp; it's an integer timestamp
            "tokenExp": exp,  # No need to convert tokenExp; it's an integer timestamp
        }

        try:
            # Ensure the secret is a valid string
            jwt_signature = jwt.encode(
                payload,
                str(settings.ZOOM_MEETING_SDK_SECRET),  # Ensure the secret is a string
                algorithm="HS256",
            )
        except Exception as e:
            return Response({"error": f"Failed to generate JWT: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        # Step 5: Return Results
        return Response(
            {
                "access_token": access_token,
                "user_id": user_id,
                "zak_token": zak_token,
                "jwt_signature": jwt_signature,
            },
            status=status.HTTP_200_OK,
        )


from django.http import JsonResponse

def oauth_callback(request):
    authorization_code = request.GET.get("code")
    if not authorization_code:
        return JsonResponse({"error": "Authorization code not provided"}, status=400)

    # Return the authorization code
    return JsonResponse({"authorization_code": authorization_code}, status=200)

#!/usr/local/autopkg/python

"""
Completely borrowed from Graham Pugh's JamfUploaderSlacker.py processor and used to capture script and EA script uploads.

https://raw.githubusercontent.com/grahampugh/jamf-upload/main/JamfUploaderProcessors/JamfUploaderSlacker.py
"""

import json
import os.path
import sys

from time import sleep
from autopkglib import ProcessorError  # pylint: disable=import-error

# to use a base module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
sys.path.insert(0, os.path.dirname(__file__))

from JamfUploaderLib.JamfUploaderBase import JamfUploaderBase  # noqa: E402


__all__ = ["JamfUploaderSlacker"]


class JamfUploaderSlacker(JamfUploaderBase):
    description = (
        "A postprocessor for AutoPkg that will send details about a recipe run "
        "to a Slack webhook based on the output of a JamfPolicyUploader "
        "process."
        "Takes elements from "
        "https://gist.github.com/devStepsize/b1b795309a217d24566dcc0ad136f784 "
        "and "
        "https://github.com/autopkg/nmcspadden-recipes/blob/master/PostProcessors/Yo.py."
    )
    input_variables = {
        "JSS_URL": {"required": False, "description": ("JSS_URL.")},
        "POLICY_CATEGORY": {"required": False, "description": ("Policy Category.")},
        "PKG_CATEGORY": {"required": False, "description": ("Package Category.")},
        "policy_name": {
            "required": False,
            "description": ("Untested product name from a jamf recipe."),
        },
        "NAME": {"required": False, "description": ("Generic product name.")},
        "pkg_name": {"required": False, "description": ("Package in policy.")},
        "version": {
            "required": False,
            "description": ("Package version."),
        },
        "script_name": {"required": False, "description": ("Script name.")},
        "script_priority": {"required": False, "description": ("Script priority.")},
        "script_category": {"required": False, "description": ("Script priority.")},
        "ea_name": {"required": False, "description": ("Extension Attribute name.")},
        "ea_script_path": {"required": False, "description": ("Extension Attribute script.")},
        "ea_data_type": {"required": False, "description": ("Extension Attribute data type.")},
        "jamfpackageuploader_summary_result": {
            "required": False,
            "description": ("Summary results of package processors."),
        },
        "jamfpolicyuploader_summary_result": {
            "required": False,
            "description": ("Summary results of policy processors."),
        },
        "jamfscriptuploader_summary_result": {
            "required": False,
            "description": ("Summary results of policy processors."),
        },
        "slack_webhook_url": {"required": True, "description": ("Slack webhook.")},
        "slack_username": {
            "required": False,
            "description": ("Slack message display name."),
            "default": "AutoPkg",
        },
        "slack_icon_url": {
            "required": False,
            "description": ("Slack display icon URL."),
            "default": "",
        },
        "slack_channel": {
            "required": False,
            "description": ("Slack channel (for overriding the default)."),
        },
        "slack_icon_emoji": {
            "required": False,
            "description": ("Slack display emoji markup."),
        },
    }
    output_variables = {}

    __doc__ = description

    def slack_status_check(self, r):
        """Return a message dependent on the HTTP response"""
        if r.status_code == 200 or r.status_code == 201:
            self.output("Slack webhook sent successfully")
            return "break"
        else:
            self.output("WARNING: Slack webhook failed to send")
            self.output(r.output, verbose_level=2)

    def main(self):
        """Do the main thing"""
        jss_url = self.env.get("JSS_URL")
        policy_category = self.env.get("POLICY_CATEGORY")
        category = self.env.get("PKG_CATEGORY")
        policy_name = self.env.get("policy_name")
        name = self.env.get("NAME")
        version = self.env.get("version")
        pkg_name = self.env.get("pkg_name")
        script_name = self.env.get("script_name")
        script_priority = self.env.get("script_priority")
        script_category = self.env.get("script_category")
        ea_name = self.env.get("ea_name")
        ea_script_path = self.env.get("ea_script_path")
        ea_data_type = self.env.get("ea_data_type")
        jamfpackageuploader_summary_result = self.env.get(
            "jamfpackageuploader_summary_result"
        )
        jamfpolicyuploader_summary_result = self.env.get(
            "jamfpolicyuploader_summary_result"
        )
        jamfscriptuploader_summary_result = self.env.get(
            "jamfscriptuploader_summary_result"
        )
        jamfextensionattributeuploader_summary_result = self.env.get(
            "jamfextensionattributeuploader_summary_result"
        )

        slack_username = self.env.get("slack_username")
        slack_icon_url = self.env.get("slack_icon_url") or ""
        slack_webhook_url = self.env.get("slack_webhook_url")
        slack_channel = self.env.get("slack_channel") or ""
        slack_icon_emoji = self.env.get("slack_icon_emoji") or ""

        selfservice_policy_name = name
        self.output(f"JSS address: {jss_url}")
        self.output(f"Title: {selfservice_policy_name}")
        self.output(f"Policy: {policy_name}")
        self.output(f"Version: {version}")
        self.output(f"Package: {pkg_name}")
        self.output(f"Package Category: {category}")
        self.output(f"Policy Category: {policy_category}")

        if jamfpackageuploader_summary_result and jamfpolicyuploader_summary_result:
            slack_text = (
                "*New Item uploaded to Jamf Pro:*\n"
                + f"URL: {jss_url}\n"
                + f"Title: *{selfservice_policy_name}*\n"
                + f"Version: *{version}*\n"
                + f"Category: *{category}*\n"
                + f"Policy Name: *{policy_name}*\n"
                + f"Package: *{pkg_name}*"
            )
        elif jamfpolicyuploader_summary_result:
            slack_text = (
                "*New Item uploaded to Jamf Pro:*\n"
                + f"URL: {jss_url}\n"
                + f"Title: *{selfservice_policy_name}*\n"
                + f"Category: *{category}*\n"
                + f"Policy Name: *{policy_name}*\n"
                + "No new package uploaded"
            )
        elif jamfpackageuploader_summary_result:
            slack_text = (
                "*New Item uploaded to Jamf Pro:*\n"
                + f"URL: {jss_url}\n"
                + f"Version: *{version}*\n"
                + f"Category: *{category}*\n"
                + f"Package: *{pkg_name}*"
            )
        elif jamfscriptuploader_summary_result:
            slack_text = (
                "*New Script uploaded to Jamf Pro:*\n"
                + f"URL: {jss_url}\n"
                + f"Script: *{script_name}*\n"
                + f"Priority: *{script_priority}*\n"
                + f"Category: *{script_category}*"
            )
        elif jamfextensionattributeuploader_summary_result:
            slack_text = (
                "*New Extension Attribute uploaded to Jamf Pro:*\n"
                + f"URL: {jss_url}\n"
                + f"EA Name: *{ea_name}*\n"
                + f"Script: *{ea_script_path}*\n"
                + f"Data Type: *{ea_data_type}*"
            )
        else:
            self.output("Nothing to report to Slack")
            return

        slack_data = {
            "text": slack_text,
            "username": slack_username,
        }
        if slack_icon_url:
            slack_data["icon_url"] = slack_icon_url
        if slack_channel:
            slack_data["channel"] = slack_channel
        if slack_icon_emoji:
            slack_data["icon_emoji"] = slack_icon_emoji

        slack_json = json.dumps(slack_data)

        count = 0
        while True:
            count += 1
            self.output(
                "Slack webhook post attempt {}".format(count),
                verbose_level=2,
            )
            r = self.curl(request="POST", url=slack_webhook_url, data=slack_json)
            # check HTTP response
            if self.slack_status_check(r) == "break":
                break
            if count > 5:
                self.output("Slack webhook send did not succeed after 5 attempts")
                self.output("\nHTTP POST Response Code: {}".format(r.status_code))
                raise ProcessorError("ERROR: Slack webhook failed to send")
            sleep(10)


if __name__ == "__main__":
    PROCESSOR = JamfUploaderSlacker()
    PROCESSOR.execute_shell()
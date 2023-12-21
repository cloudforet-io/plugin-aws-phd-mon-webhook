import logging
import json
from datetime import datetime
from typing import Union

from plugin.manager.event_manager import ParseManager

_LOGGER = logging.getLogger("spaceone")


class PersonalHealthDashboardManager(ParseManager):
    webhook_type = "AWS_PHD"

    def parse(self, raw_data: dict) -> dict:
        """

        :param raw_data:
        :return EventResponse:
            "results": EventResponse
        """
        results = []

        _LOGGER.debug(f"[AWSPersonalHealthDashboard] parse => {json.dumps(raw_data, indent=2)}")

        event_type_category = raw_data.get("detail", {}).get("eventTypeCategory", "")

        event: dict = {
            'event_key': self.generate_event_key(raw_data),
            'event_type': self.get_event_type(raw_data),
            'severity': self.get_severity(event_type_category),
            'resource': self._get_resource(raw_data),
            'description': self._generate_description(raw_data),
            'title': self._change_string_format(raw_data.get("detail", {}).get("eventTypeCode", "")),
            'rule': event_type_category,
            'occurred_at': self.convert_to_iso8601(raw_data.get("detail", {}).get("startTime")),
            'account': raw_data.get("account", ""),
            'additional_info': self.get_additional_info(raw_data)
        }

        results.append(event)
        _LOGGER.debug(f"[AWSPersonalHealthDashboard] parse => {event}")

        return {
            "results": results
        }

    def generate_event_key(self, raw_data: dict) -> str:
        return raw_data.get("detail", {}).get("eventArn", "")

    def get_event_type(self, raw_data: dict) -> str:
        return "ALERT"

    def get_severity(self, event_type_category: str) -> str:
        """
        Severity:
            - issue, scheduledChange -> ERROR
            - accountNotification -> INFO
        """

        if event_type_category in ["issue", "scheduledChange"]:
            severity_flag = "ERROR"
        else:
            severity_flag = "INFO"

        return severity_flag

    @staticmethod
    def _change_string_format(event_type_code):
        title = event_type_code.replace('_', ' ').title()
        return title

    @staticmethod
    def _generate_description(raw_data: dict) -> str:
        detail_event = raw_data.get("detail", {})
        account_id = raw_data.get("account", "")

        text = [description.get("latestDescription", "").replace("\\\\n", "\n").replace("\\n", "\n")
                for description in detail_event.get("eventDescription", "")]
        full_text = ' '.join(text)

        affected_entities = [affected_entity.get("entityValue", "")
                             for affected_entity in detail_event.get("affectedEntities", [])]
        if affected_entities:
            affected_entities_names_str = '\n - '.join(affected_entities)
            description = f"{full_text} (Account:{account_id})\n\nAffected Entities:\n - {affected_entities_names_str}"
        else:
            description = f"{full_text} (Account:{account_id})\n\nAffected Entities: None"

        return description

    def get_additional_info(self, raw_data: dict) -> dict:
        additional_info = {}
        additional_info_key = ["id", "account", "region", "service", "eventTypeCode", "affectedEntities"]
        for _key in raw_data:
            if _key in additional_info_key and raw_data.get(_key):
                additional_info.update({_key: raw_data.get(_key)})
            if _key == "detail":
                detail_event = raw_data.get(_key)
                for detail_key in detail_event:
                    if detail_key in additional_info_key:
                        if detail_key == "affectedEntities":
                            affected_entities = [affected_entity.get("entityValue", "")
                                                 for affected_entity in detail_event.get(detail_key)]
                            additional_info.update({detail_key: affected_entities})
                        else:
                            additional_info.update({detail_key: detail_event.get(detail_key)})

        return additional_info

    @staticmethod
    def _get_resource(raw_data: dict) -> dict:
        return {
            "resource_id": raw_data.get("detail", {}).get("eventArn", ""),
            "resource_type": raw_data.get("source", "aws.health")
        }

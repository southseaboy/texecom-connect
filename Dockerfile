FROM python:3-alpine

RUN apk upgrade --update \
  && apk add -U tzdata \
  && cp /usr/share/zoneinfo/Europe/London /etc/localtime \
  && apk del tzdata \
  && rm -rf /var/cache/apk/*

WORKDIR /usr/src/app

COPY alarm-monitor.py ./
COPY texecomConnect.py ./
COPY texecomDefines.py ./
COPY area.py ./
COPY user.py ./
COPY zone.py ./
COPY hexdump.py ./

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

CMD [ "python", "alarm-monitor.py" ]
ENV TEXHOST=10.0.0.241 TEXPORT=10046 UDLPASSWORD=1234 BROKER_URL=10.0.50.5
ENV BROKER_USER=TexeMQTT BROKER_PASS=S1lentAlarm
ENV MQTT_ROOT_TOPIC=texecom 
ENV MQTT_CONFIG_TOPIC=homeassistant 
ENV MQTT_AREAS=all,intruder,fire_CO,unused_3,unused_4 
ENV MQTT_AREAMAPS=0F000000000000,01000000000000,02000000000000,04000000000000,08000000000000
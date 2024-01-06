/**
 * Copyright © 2016-2023 The Thingsboard Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.thingsboard.mqtt.broker.service.mqtt.persistence.device.queue;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.thingsboard.mqtt.broker.common.util.ThingsBoardExecutors;
import org.thingsboard.mqtt.broker.gen.queue.QueueProtos;
import org.thingsboard.mqtt.broker.queue.TbQueueCallback;
import org.thingsboard.mqtt.broker.queue.TbQueueMsgMetadata;
import org.thingsboard.mqtt.broker.queue.common.TbProtoQueueMsg;
import org.thingsboard.mqtt.broker.queue.provider.DevicePersistenceMsgQueueFactory;
import org.thingsboard.mqtt.broker.queue.publish.TbPublishServiceImpl;
import org.thingsboard.mqtt.broker.service.analysis.ClientLogger;
import org.thingsboard.mqtt.broker.service.processing.PublishMsgCallback;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.util.concurrent.ExecutorService;

@Slf4j
@Service
@RequiredArgsConstructor
public class DeviceMsgQueuePublisherImpl implements DeviceMsgQueuePublisher {

    private final ClientLogger clientLogger;
    private final DevicePersistenceMsgQueueFactory devicePersistenceMsgQueueFactory;

    private TbPublishServiceImpl<QueueProtos.PublishMsgProto> publisher;

    @Value("${mqtt.handler.device_msg_callback_threads:0}")
    private int threadsCount;

    private ExecutorService callbackProcessor;

    @PostConstruct
    public void init() {
        this.callbackProcessor = ThingsBoardExecutors.initExecutorService(threadsCount, "device-msg-callback-processor");
        this.publisher = TbPublishServiceImpl.<QueueProtos.PublishMsgProto>builder()
                .queueName("deviceMsg")
                .producer(devicePersistenceMsgQueueFactory.createProducer())
                .build();
        this.publisher.init();
    }

    @Override
    public void sendMsg(String clientId, TbProtoQueueMsg<QueueProtos.PublishMsgProto> queueMsg, PublishMsgCallback callback) {
        clientLogger.logEvent(clientId, this.getClass(), "Sending msg in DEVICE Queue");
        publisher.send(queueMsg,
                new TbQueueCallback() {
                    @Override
                    public void onSuccess(TbQueueMsgMetadata metadata) {
                        callbackProcessor.submit(() -> {
                            clientLogger.logEvent(clientId, this.getClass(), "Sent msg in DEVICE Queue");
                            if (log.isTraceEnabled()) {
                                log.trace("[{}] Successfully sent publish msg to the queue.", clientId);
                            }
                            callback.onSuccess();
                        });
                    }

                    @Override
                    public void onFailure(Throwable t) {
                        callbackProcessor.submit(() -> {
                            log.error("[{}] Failed to send publish msg to the queue for MQTT topic {}.",
                                    clientId, queueMsg.getValue().getTopicName(), t);
                            callback.onFailure(t);
                        });
                    }
                });
    }

    @PreDestroy
    public void destroy() {
        publisher.destroy();
        if (callbackProcessor != null) {
            callbackProcessor.shutdownNow();
        }
    }
}

package com.zohorecruit.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JsonConverter {
    private static final Logger logger
            = LoggerFactory.getLogger(JsonConverter.class);


    public static <T> String toJson(T obj, boolean formatOutput) {
        String jsonString = "";
        JsonMapper jsonMapper = new JsonMapper();
        try {
            if (formatOutput) {
                jsonString = jsonMapper.findAndRegisterModules().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(obj);
            } else {
                jsonString = jsonMapper.findAndRegisterModules().writeValueAsString(obj);
            }
        } catch (JsonProcessingException e) {
            // TODO Auto-generated catch block
            // e.printStackTrace();
            logger.error("error converting object to json", e);
        }
        return jsonString;

    }

    public static <T> T toObj(String jsonString, Class<T> objClass) {
        T obj = null;
        JsonMapper jsonMapper = new JsonMapper();
        try {
            obj = jsonMapper.findAndRegisterModules()
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                    .readValue(jsonString, objClass);
        } catch (JsonProcessingException e) {
            logger.error("error converting json {} to object", jsonString, e);
        }
        return obj;
    }

    public static <T> T toObj(JsonNode jsonNode, Class<T> objClass) {
        T obj = null;
        JsonMapper jsonMapper = new JsonMapper();
        jsonMapper.findAndRegisterModules().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        try {
            obj = jsonMapper.treeToValue(jsonNode, objClass);
        } catch (JsonProcessingException e) {
            logger.error("error converting jsonNode to object", e);
        }
        return obj;
    }

    public static JsonNode toJsonNode(String json) {
        JsonNode jsonNode = null;
        JsonMapper jsonMapper = new JsonMapper();
        jsonMapper.findAndRegisterModules().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        try {
            jsonNode = jsonMapper.readTree(json);
        } catch (JsonProcessingException e) {
            logger.error("error converting jsonNode to object", e);
        }
        return jsonNode;
    }
}

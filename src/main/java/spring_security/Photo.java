package spring_security;

import lombok.Data;

@Data
public class Photo {

    private String photoId;
    private String photoTitle;
    private String photoDescription;
    private String userId;
}

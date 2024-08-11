package backend.like_house.domain.post.service;
import backend.like_house.domain.post.dto.PostDTO.PostResponse.*;
import backend.like_house.domain.user.entity.User;

import java.util.List;

public interface PostQueryService {
    PostCursorDataListResponse getPostsByFamilySpace(Long familySpaceId, User user, Long cursor, Integer size);
    GetPostDetailResponse getPostDetail(Long postId, User user);
    MyPostCursorDataListResponse getMyPosts(User user, Long cursor, Integer size);
}

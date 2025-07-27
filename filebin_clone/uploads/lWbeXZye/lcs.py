def lengthOfLongestSubstring(s):
        longest = 0
        current_length = 0
        my_set = set()
        left = 0
        right = 0
        for c in s:
            if c in my_set:
                longest = max(longest,current_length)
                while c in my_set and left <= right and right<len(s):
                    my_set.remove(s[left])
                    left+=1
                    current_length-=1
                my_set.add(c)
                current_length+=1

               
                
            else:
                my_set.add(c)
                right+=1
                current_length+=1

        longest = max(longest,current_length)
        return longest
        

lengthOfLongestSubstring("pwwkew")
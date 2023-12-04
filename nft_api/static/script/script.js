document.addEventListener('DOMContentLoaded', function() {

    const previewImage = (event) => {
    const imageFiles = event.target.files;
    const imageFilesLength = imageFiles.length;
    
    if (imageFilesLength > 0) {
        const imageSrc = URL.createObjectURL(imageFiles[0]);
        const imagePreviewElement = document.querySelector("#preview-selected-image");
        const uploadButton = document.querySelector("label[for='file-upload']");
        
        imagePreviewElement.src = imageSrc;
        imagePreviewElement.style.display = "block";
        
        // Hide the "Upload" button
        uploadButton.style.display = "none";
    }
  };
  
  const nft = ["https://news.johncabot.edu/wp-content/uploads/2022/03/nft1.png","https://qph.cf2.quoracdn.net/main-qimg-0e1b650d51ec242e5dceb3eb82b8aaa4","https://miro.medium.com/v2/resize:fit:1400/1*C7yfQZxIoGminCReKdz2Vg.jpeg","https://thumbor.forbes.com/thumbor/fit-in/900x510/https://www.forbes.com/advisor/in/wp-content/uploads/2022/03/monkey-g412399084_1280.jpg","https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcT-xTSC6LxkBGTT-nosr6sb_MekBIBbN4GxJg&usqp=CAU","https://akm-img-a-in.tosshub.com/businesstoday/images/story/202111/ab-nft-sixteen_nine.jpg?size=1200:675","https://cdn.pixabay.com/photo/2022/03/01/02/51/galaxy-7040416_1280.png","https://accelerationeconomy.com/wp-content/uploads/2022/11/a-picture-containing-text-colorful-description-a.png","https://hacker9-cdn.b-cdn.net/wp-content/uploads/2021/12/What-Exactly-Is-NFT-design.jpg"]
  
  const randomNumber = Math.floor(Math.random() * 9) + 1;
  const img_url = nft[randomNumber];
  const image_1_id = document.getElementById('container-index-img-bg');
  const image_2_id = document.getElementById('index-img-bg');
  console.log(nft.length)
  console.log(randomNumber)
  
  image_1_id.style.backgroundImage =`url(${img_url})`
  image_2_id.src=img_url;
  
  // to change the color accord to the image
  // const resultDiv = document.getElementById('result-color');
  // const img = new Image();
  //         img.crossOrigin = "Anonymous";
  //         img.src = img_url;
  
          // img.onload = function () {
          //     const canvas = document.createElement('canvas');
          //     const ctx = canvas.getContext('2d');
  
          //     canvas.width = img.width;
          //     canvas.height = img.height;
  
          //     ctx.drawImage(img, 0, 0, img.width, img.height);
  
          //     const data = ctx.getImageData(0, 0, img.width, img.height).data;
  
          //     const pixelCount = data.length / 4; // Each pixel has RGBA values, so divide by 4
  
          //     let redSum = 0;
          //     let greenSum = 0;
          //     let blueSum = 0;
  
          //     for (let i = 0; i < data.length; i += 4) {
          //         redSum += data[i];
          //         greenSum += data[i + 1];
          //         blueSum += data[i + 2];
          //     }
  
          //     const averageRed = Math.round(redSum / pixelCount)+1;
          //     const averageGreen = Math.round(greenSum / pixelCount)+1;
          //     const averageBlue = Math.round(blueSum / pixelCount)+1;
  
          //     const dominantColor = `rgba(0, ${averageGreen}, 256)`;
  
          //     resultDiv.style.color = `${dominantColor}`;
          //     console.log(dominantColor);
          // };
  
     document.addEventListener('DOMContentLoaded', function () {
      const loginBtn = document.getElementById('loginBtn');
      const loginPopup = document.getElementById('loginPopup');
      const closePopupBtn = document.getElementById('closePopupBtn');
  
      loginBtn.addEventListener('click', function () {
          loginPopup.classList.add('show'); // Add the 'show' class to display the pop-up
      });
  
      closePopupBtn.addEventListener('click', function () {
          loginPopup.classList.remove('show'); // Remove the 'show' class to hide the pop-up
      });
  
      document.addEventListener('click', function (event) {
          if (event.target === loginPopup) {
              loginPopup.classList.remove('show'); // Remove the 'show' class to hide the pop-up
          }
      });
  });

});
